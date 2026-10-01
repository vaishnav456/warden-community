package main

// History is opt-in via signed space grants. Blobs remain encrypted with their
// original path AAD; descriptors are separately encrypted and authenticated.
import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var historyID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var historyDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// API files receive an encryption suffix and cannot create this raw marker.
// It distinguishes internal history from similarly named real user folders.
func isHomeHistoryDirectory(path string) bool {
	info, err := os.Lstat(filepath.Join(path, ".warden-history-v1"))
	return err == nil && info.Mode().IsRegular() && info.Size() == 0
}

type homeVersion struct {
	ID        string `json:"id"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	ModTime   int64  `json:"mod_time"`
	SavedAt   int64  `json:"saved_at"`
	ExpiresAt int64  `json:"expires_at"`
	Deleted   bool   `json:"deleted"`
}

func historyPaths(rel, id string) (string, string, error) {
	data, _, err := pathsFor(rel)
	if err != nil {
		return "", "", err
	}
	if !historyID.MatchString(id) {
		return "", "", errors.New("invalid version ID")
	}
	directory := data + ".history"
	if info, err := os.Lstat(directory); err == nil && info.IsDir() && !isHomeHistoryDirectory(directory) {
		return "", "", errors.New("history path collides with an existing synced directory; rename that directory before enabling history")
	}
	for _, path := range []string{directory, filepath.Join(directory, id+".record"), filepath.Join(directory, id+".blob")} {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("symlink history path")
		} else if err != nil && !os.IsNotExist(err) {
			return "", "", err
		}
	}
	return filepath.Join(directory, id+".blob"), filepath.Join(directory, id+".record"), nil
}

func versionAAD(rel, id string) []byte {
	return []byte("warden-home:history:v1:" + filepath.ToSlash(rel) + ":" + id)
}

func readHomeVersion(rel, id string) (homeVersion, error) {
	_, record, err := historyPaths(rel, id)
	if err != nil {
		return homeVersion{}, err
	}
	info, err := os.Lstat(record)
	if err != nil {
		return homeVersion{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 {
		return homeVersion{}, errors.New("invalid history descriptor")
	}
	raw, err := os.ReadFile(record)
	if err != nil {
		return homeVersion{}, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return homeVersion{}, errors.New("invalid history descriptor")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], versionAAD(rel, id))
	if err != nil {
		return homeVersion{}, err
	}
	var v homeVersion
	if json.Unmarshal(plain, &v) != nil || v.ID != id || v.Size < 0 || !historyDigest.MatchString(v.SHA256) || v.ExpiresAt <= v.SavedAt {
		return v, errors.New("invalid history record")
	}
	return v, nil
}

// Caller holds the space lock. Failure leaves the active copy untouched.
func archiveHomeVersion(rel string, days int, deleted bool) error {
	if days == 0 {
		return nil
	}
	if days < 0 || days > 365 {
		return errors.New("invalid history retention")
	}
	data, meta, err := pathsFor(rel)
	if err != nil {
		return err
	}
	m := loadMeta(meta)
	if !m.Exists {
		return nil
	}
	if !m.Valid {
		return errors.New("invalid stored metadata")
	}
	{
		f, err := os.Open(data)
		if err != nil {
			return err
		}
		actual, digestErr := plaintextDigest(f, rel)
		f.Close()
		if digestErr != nil {
			return digestErr
		}
		if m.SHA256 != "" && !strings.EqualFold(m.SHA256, actual) {
			return errors.New("stored history source does not match authenticated content hash")
		}
		m.SHA256 = actual
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return err
	}
	id := hex.EncodeToString(token)
	blob, record, err := historyPaths(rel, id)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(blob), 0700); err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(filepath.Dir(blob), ".warden-history-v1"), nil, 0600); err != nil {
		return err
	}
	src, err := os.Open(data)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(blob, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, src)
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		os.Remove(blob)
		return errors.New("could not save encrypted history")
	}
	now := time.Now().Unix()
	v := homeVersion{ID: id, SHA256: m.SHA256, Size: m.Size, ModTime: m.ModTime, SavedAt: now, ExpiresAt: now + int64(days)*86400, Deleted: deleted}
	plain, _ := json.Marshal(v)
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	if err = atomicWrite(record, aead.Seal(nonce, nonce, plain, versionAAD(rel, id)), 0600); err != nil {
		return err
	}
	return nil
}

func listHomeVersions(rel string) ([]homeVersion, error) {
	if _, _, err := historyPaths(rel, strings.Repeat("0", 32)); err != nil {
		return nil, err
	}
	data, _, err := pathsFor(rel)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(data + ".history")
	if os.IsNotExist(err) {
		return []homeVersion{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := []homeVersion{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".record") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".record")
		v, err := readHomeVersion(rel, id)
		if err != nil {
			return nil, err
		}
		if v.ExpiresAt > time.Now().Unix() {
			result = append(result, v)
			if len(result) > 1000 {
				return nil, errors.New("history has more than 1000 versions; narrow retention before browsing")
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SavedAt > result[j].SavedAt })
	return result, nil
}

// Physical encrypted history bytes count against the Home space quota.
func historyUsageAndCleanup(prefix string, cleanup bool) (int64, error) {
	data, _, err := pathsFor(prefix)
	if err != nil {
		return 0, err
	}
	root := strings.TrimSuffix(data, ".whome")
	var used int64
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if os.IsNotExist(walkErr) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink history path")
		}
		if info.IsDir() || !strings.HasSuffix(filepath.Dir(path), ".whome.history") || !isHomeHistoryDirectory(filepath.Dir(path)) {
			return nil
		}
		rel, err := filepath.Rel(cfg.Root, strings.TrimSuffix(filepath.Dir(path), ".whome.history"))
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".record") {
			id := strings.TrimSuffix(filepath.Base(path), ".record")
			v, err := readHomeVersion(filepath.ToSlash(rel), id)
			if err != nil {
				return err
			}
			if cleanup && v.ExpiresAt <= time.Now().Unix() {
				blob, record, err := historyPaths(filepath.ToSlash(rel), id)
				if err != nil {
					return err
				}
				if err = os.Remove(blob); err != nil && !os.IsNotExist(err) {
					return err
				}
				if err = os.Remove(record); err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			}
		}
		// Re-stat: an expired descriptor may have removed this blob already.
		if current, err := os.Stat(path); err == nil {
			if current.Size() < 0 || current.Size() > math.MaxInt64-used {
				return errors.New("history size overflow")
			}
			used += current.Size()
		} else if !os.IsNotExist(err) {
			return err
		}
		return nil
	})
	if err == nil && cleanup {
		return historyUsageAndCleanup(prefix, false)
	}
	return used, err
}

func historyGrowth(rel string, days int) (int64, error) {
	if days == 0 {
		return 0, nil
	}
	if days < 0 || days > 365 {
		return 0, errors.New("invalid history retention")
	}
	data, meta, err := pathsFor(rel)
	if err != nil {
		return 0, err
	}
	m := loadMeta(meta)
	if !m.Exists {
		return 0, nil
	}
	if !m.Valid {
		return 0, errors.New("invalid metadata")
	}
	info, err := os.Stat(data)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	v := homeVersion{ID: strings.Repeat("0", 32), SHA256: strings.Repeat("0", 64), Size: m.Size, ModTime: m.ModTime, SavedAt: now, ExpiresAt: now + int64(days)*86400}
	plain, _ := json.Marshal(v)
	return info.Size() + int64(len(plain)+aead.NonceSize()+aead.Overhead()), nil
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	permission := "read"
	if r.Method == http.MethodPost {
		permission = "write"
	} else if r.Method != http.MethodGet {
		http.Error(w, "method", 405)
		return
	}
	g, err := verifyGrant(r, bearer(r), rel, permission)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	storageMu.Lock()
	defer storageMu.Unlock()
	release, err := acquireSpaceLock(g.Prefix)
	if err != nil {
		http.Error(w, "storage busy", 503)
		return
	}
	defer release()
	if _, err = historyUsageAndCleanup(g.Prefix, true); err != nil {
		http.Error(w, "history cleanup failed", 500)
		return
	}
	if r.Method == http.MethodGet {
		versions, err := listHomeVersions(rel)
		if err != nil {
			http.Error(w, "history unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(versions)
		return
	}
	id := r.URL.Query().Get("version")
	v, err := readHomeVersion(rel, id)
	if err != nil || v.ExpiresAt <= time.Now().Unix() {
		http.Error(w, "version not found", 404)
		return
	}
	current, err := storedVersion(rel)
	if err != nil {
		http.Error(w, "current version invalid", 500)
		return
	}
	if r.Header.Get("X-Warden-Expected-Version") != current {
		http.Error(w, "file changed; refresh history", 412)
		return
	}
	blob, _, _ := historyPaths(rel, id)
	src, err := os.Open(blob)
	if err != nil {
		http.Error(w, "history unavailable", 500)
		return
	}
	defer src.Close()
	// Bounded temporary plaintext lives only in memory/pipe, never on disk.
	reader, writer := io.Pipe()
	go func() { writer.CloseWithError(decryptStreamForPath(writer, src, rel)) }()
	defer reader.Close()
	readd := ""
	if deletion, _ := readHomeDeletion(rel); deletion != nil {
		readd = homeDeletionVersion(deletion)
	}
	status, err := storeAuthorizedFileVerified(rel, reader, v.ModTime, g, v.SHA256, readd)
	if err != nil {
		http.Error(w, fmt.Sprint(err), status)
		return
	}
	w.Header().Set("X-Warden-SHA256", v.SHA256)
	w.WriteHeader(204)
}

func storedVersion(rel string) (string, error) {
	deletion, err := readHomeDeletion(rel)
	if err != nil {
		return "", err
	}
	if deletion != nil {
		return homeDeletionVersion(deletion), nil
	}
	data, meta, err := pathsFor(rel)
	if err != nil {
		return "", err
	}
	m := loadMeta(meta)
	if !m.Exists {
		return "", nil
	}
	if !m.Valid {
		return "", errors.New("invalid metadata")
	}
	if m.SHA256 != "" {
		return m.SHA256, nil
	}
	f, err := os.Open(data)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return plaintextDigest(f, rel)
}
