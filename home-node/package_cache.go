package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var packageCacheMu sync.Mutex
var packageCacheHTTPClient = &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}

func packageCacheRoot() (string, error) {
	root := filepath.Join(cfg.Root, ".warden-package-cache")
	if _, err := absoluteRealDirectory(root); err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	return root, nil
}
func cacheDigest(path, sha string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("invalid package cache object")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if err = decryptStreamForPath(hash, file, "package-cache/"+sha); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != sha {
		return errors.New("cached package hash mismatch")
	}
	return nil
}
func reserveCacheSpace(root string, need int64) error {
	if need <= 0 || need > cfg.PackageCacheMaxBytes {
		return errors.New("package exceeds configured cache quota")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	type item struct {
		path     string
		size     int64
		modified time.Time
	}
	files := []item{}
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		digest := strings.TrimSuffix(name, ".blob")
		raw, decodeErr := hex.DecodeString(digest)
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if decodeErr != nil || len(raw) != 32 || name != digest+".blob" || !info.Mode().IsRegular() {
			return errors.New("unexpected object in internal package cache")
		}
		if info.Size() > math.MaxInt64-total {
			return errors.New("cache usage overflow")
		}
		total += info.Size()
		files = append(files, item{filepath.Join(root, name), info.Size(), info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modified.Before(files[j].modified) })
	for _, file := range files {
		if need <= cfg.PackageCacheMaxBytes-total {
			break
		}
		// Only validated internal cache blobs are evicted; originals remain on the server.
		if err = os.Remove(file.path); err != nil {
			return err
		}
		total -= file.size
	}
	if need > cfg.PackageCacheMaxBytes-total {
		return errors.New("package cache quota exhausted")
	}
	return nil
}
func fetchCachedPackage(root string, g grant) (string, error) {
	path := filepath.Join(root, g.PackageSHA256+".blob")
	if err := cacheDigest(path, g.PackageSHA256); err == nil {
		now := time.Now()
		_ = os.Chtimes(path, now, now)
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	base, err := url.Parse(cfg.WardenURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		return "", errors.New("package source requires configured HTTPS server")
	}
	app, err := url.Parse(g.AppID)
	if err != nil || app.Path != g.AppID || strings.ContainsAny(g.AppID, "/\\?#") {
		return "", errors.New("invalid package ID")
	}
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.WardenURL, "/")+"/api/home-node/packages/"+url.PathEscape(g.AppID), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("X-Warden-Home-Key", cfg.NodeKey)
	response, err := packageCacheHTTPClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("package source HTTP %d", response.StatusCode)
	}
	estimate := g.MaxFileBytes + ((g.MaxFileBytes/chunkSize + 2) * int64(aead.Overhead()+aead.NonceSize()+4)) + 128
	if err = reserveCacheSpace(root, estimate); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(root, ".package-")
	if err != nil {
		return "", err
	}
	temp := file.Name()
	defer os.Remove(temp)
	hash := sha256.New()
	size, err := encryptStreamForPath(file, io.TeeReader(io.LimitReader(response.Body, g.MaxFileBytes+1), hash), "package-cache/"+g.PackageSHA256)
	if err == nil && (size != g.MaxFileBytes || hex.EncodeToString(hash.Sum(nil)) != g.PackageSHA256) {
		err = errors.New("package source size/hash mismatch")
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if err = os.Rename(temp, path); err != nil {
		return "", err
	}
	return path, nil
}
func handlePackageCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	sha := r.URL.Query().Get("sha256")
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != 32 || sha != strings.ToLower(sha) {
		http.Error(w, "invalid digest", 400)
		return
	}
	g, err := verifyGrant(r, bearer(r), "packages/"+sha, "package")
	if err != nil || g.Audience != "warden-package-cache" || g.PackageSHA256 != sha || g.MaxFileBytes <= 0 || g.MaxFileBytes > 500*1024*1024 {
		http.Error(w, "invalid package authorization", 403)
		return
	}
	if cfg.PackageCacheMaxBytes <= 0 {
		http.Error(w, "package cache disabled", 409)
		return
	}
	packageCacheMu.Lock()
	defer packageCacheMu.Unlock()
	root, err := packageCacheRoot()
	if err != nil {
		http.Error(w, "cache unavailable", 503)
		return
	}
	path, err := fetchCachedPackage(root, g)
	if err != nil {
		http.Error(w, "cache fetch/verification failed", 502)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, "cache unavailable", 503)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Warden-SHA256", sha)
	_ = decryptStreamForPath(w, file, "package-cache/"+sha)
}
