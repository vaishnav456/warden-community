package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("path")
	g, err := verifyGrant(r, bearer(r), prefix, "read")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Complete already-confirmed deletions from older releases before reporting
	// sync success. This does not infer deletions from missing endpoint files.
	storageMu.Lock()
	release, err := acquireSpaceLock(g.Prefix)
	if err == nil {
		err = cleanupHomeDeletions(prefix)
		if err == nil {
			_, err = historyUsageAndCleanup(prefix, true)
		}
		release()
	}
	storageMu.Unlock()
	if err != nil {
		http.Error(w, "deletion cleanup failed; retry sync", http.StatusServiceUnavailable)
		return
	}
	entries, err := listStoredEntries(prefix, r.URL.Query().Get("include_directories") == "1")
	if err == nil && r.URL.Query().Get("include_deletions") == "1" {
		entries, err = appendHomeDeletions(prefix, entries)
	}
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Warden-Deletion-Tracking", "1")
	w.Header().Set("X-Warden-Conditional-Writes", "1")
	_ = json.NewEncoder(w).Encode(entries)
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	permission := map[string]string{http.MethodGet: "read", http.MethodPut: "write", http.MethodDelete: "delete"}[r.Method]
	if permission == "" {
		http.Error(w, "method", 405)
		return
	}
	g, err := verifyGrant(r, bearer(r), rel, permission)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	data, meta, err := pathsFor(rel)
	if err != nil {
		http.Error(w, "bad path", 400)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if deletion, err := readHomeDeletion(rel); err != nil {
			http.Error(w, "invalid deletion record", 500)
			return
		} else if deletion != nil {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(data)
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "read failed", 500)
			return
		}
		defer f.Close()
		m := loadMeta(meta)
		if !m.Valid {
			http.Error(w, "stored file metadata authentication failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Warden-Mtime", fmt.Sprint(m.ModTime))
		if m.SHA256 != "" {
			w.Header().Set("X-Warden-SHA256", m.SHA256)
		}
		w.Header().Set("Content-Length", fmt.Sprint(m.Size))
		if err := decryptStreamForPath(w, f, rel); err != nil {
			log.Printf("decrypt %s: %v", rel, err)
		}
	case http.MethodPut:
		if g.MaxFileBytes > 0 && r.ContentLength > g.MaxFileBytes {
			http.Error(w, "file exceeds this space's per-file limit", http.StatusRequestEntityTooLarge)
			return
		}
		mtime, _ := time.Parse(time.RFC3339, r.Header.Get("X-Warden-Mtime"))
		storageMu.Lock()
		release, lockErr := acquireSpaceLock(g.Prefix)
		if lockErr != nil {
			storageMu.Unlock()
			http.Error(w, "shared storage is busy", http.StatusServiceUnavailable)
			return
		}
		current, currentErr := storedVersion(rel)
		if currentErr != nil || (r.Header.Get("If-Match") != "" && strings.Trim(r.Header.Get("If-Match"), "\"") != current) || (r.Header.Get("If-None-Match") == "*" && current != "") {
			release()
			storageMu.Unlock()
			http.Error(w, "file changed since sync; retry safely", 412)
			return
		}
		status, writeErr := storeAuthorizedFileVerified(rel, r.Body, mtime.Unix(), g, "", r.Header.Get("X-Warden-Readd-Version"))
		if writeErr == nil {
			w.Header().Set("X-Warden-SHA256", loadMeta(meta).SHA256)
		}
		release()
		storageMu.Unlock()
		if writeErr != nil {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.WriteHeader(204)
	case http.MethodDelete:
		storageMu.Lock()
		release, lockErr := acquireSpaceLock(g.Prefix)
		if lockErr != nil {
			storageMu.Unlock()
			http.Error(w, "shared storage is busy", http.StatusServiceUnavailable)
			return
		}
		status, deleteErr := confirmHomeDeletion(rel, strings.Trim(r.Header.Get("If-Match"), "\""), g)
		if deleteErr == nil {
			if deletion, err := readHomeDeletion(rel); err == nil && deletion != nil {
				w.Header().Set("X-Warden-Deletion-Version", homeDeletionVersion(deletion))
			}
		}
		release()
		storageMu.Unlock()
		if deleteErr != nil {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.WriteHeader(status)
	}
}
