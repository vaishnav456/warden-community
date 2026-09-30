package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func createStoredDirectory(rel string) error {
	// Validate the real directory component, not a fictitious .whome sibling.
	data, _, err := pathsFor(strings.TrimRight(rel, "/") + "/.warden-directory-sentinel")
	if err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(data), 0700)
}

func handleDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	rel := r.URL.Query().Get("path")
	g, err := verifyGrant(r, bearer(r), rel, "write")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	storageMu.Lock()
	defer storageMu.Unlock()
	release, err := acquireSpaceLock(g.Prefix)
	if err != nil {
		http.Error(w, "shared storage is busy", http.StatusServiceUnavailable)
		return
	}
	defer release()
	if err := createStoredDirectory(rel); err != nil {
		http.Error(w, "cannot create folder", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
