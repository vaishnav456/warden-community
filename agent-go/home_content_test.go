package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func homeTestDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestHomeHashDetectsEqualSizeAndTimestampEdits(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "changed.txt")
	os.WriteFile(path, []byte("local!"), 0600)
	stamp := time.Unix(1700000000, 0)
	os.Chtimes(path, stamp, stamp)
	puts, gets := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/changed.txt", Size: 6, ModTime: stamp.Unix(), SHA256: homeTestDigest([]byte("remote"))}})
			return
		}
		if r.Method == http.MethodPut {
			puts++
			data, _ := io.ReadAll(r.Body)
			if string(data) != "local!" {
				t.Error("local edit lost")
			}
			w.Header().Set("X-Warden-SHA256", homeTestDigest(data))
			w.WriteHeader(204)
			return
		}
		gets++
		io.WriteString(w, "remote")
	}))
	defer server.Close()
	r, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client())
	if err != nil || r.Uploaded != 1 || puts != 1 || gets != 0 {
		t.Fatalf("same-stat content edit missed: %+v %v", r, err)
	}
}

func TestHomeHashMismatchPreservesLocalCopy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file.txt")
	os.WriteFile(path, []byte("old"), 0600)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/file.txt", Size: 4, ModTime: 1700000000, SHA256: homeTestDigest([]byte("good"))}})
			return
		}
		io.WriteString(w, "evil")
	}))
	defer server.Close()
	r, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", AccessMode: "read", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL}, homeMapping{Target: "Documents"}, root, server.Client())
	data, _ := os.ReadFile(path)
	if err == nil || r.Failed != 1 || r.Downloaded != 0 || string(data) != "old" {
		t.Fatalf("unverified download replaced local copy: %+v %v", r, err)
	}
}

func TestHomeNestedFilesAndEmptyFoldersRoundTrip(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "nested", "empty"), 0700)
	os.WriteFile(filepath.Join(root, "nested", "file.txt"), []byte("hello"), 0600)
	entries := []homeRemoteFile{}
	files := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode(entries)
			return
		}
		path := r.URL.Query().Get("path")
		if r.URL.Path == "/v1/directory" {
			entries = append(entries, homeRemoteFile{Path: path, IsDir: true})
			w.WriteHeader(204)
			return
		}
		if r.Method == http.MethodPut {
			data, _ := io.ReadAll(r.Body)
			files[path] = data
			entries = append(entries, homeRemoteFile{Path: path, Size: int64(len(data)), ModTime: 1700000000, SHA256: homeTestDigest(data)})
			w.Header().Set("X-Warden-SHA256", homeTestDigest(data))
			w.WriteHeader(204)
			return
		}
		w.Write(files[path])
	}))
	defer server.Close()
	space := homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}
	node := homeNode{LocalURL: server.URL, Writable: true}
	upload, err := syncHomeMappingFiles(space, node, homeMapping{Target: "Documents"}, root, server.Client())
	if err != nil || upload.Uploaded != 1 || upload.FoldersCreated != 2 {
		t.Fatalf("folder upload failed: %+v %v", upload, err)
	}
	destination := t.TempDir()
	download, err := syncHomeMappingFiles(space, node, homeMapping{Target: "Documents"}, destination, server.Client())
	info, statErr := os.Stat(filepath.Join(destination, "nested", "empty"))
	data, _ := os.ReadFile(filepath.Join(destination, "nested", "file.txt"))
	if err != nil || statErr != nil || !info.IsDir() || download.Downloaded != 1 || string(data) != "hello" {
		t.Fatalf("folder restore failed: %+v %v", download, err)
	}
	idle, err := syncHomeMappingFiles(space, node, homeMapping{Target: "Documents"}, destination, server.Client())
	if err != nil || idle.Uploaded+idle.Downloaded+idle.FoldersCreated != 0 || idle.Unchanged != 1 {
		t.Fatalf("unchanged folder re-transferred: %+v %v", idle, err)
	}
}

func TestHomeLegacyNodeComparisonUsesContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file.txt")
	os.WriteFile(path, []byte("same"), 0600)
	info, _ := os.Stat(path)
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gets++; io.WriteString(w, "same") }))
	defer server.Close()
	equal, err := homeContentMatches(server.Client(), homeNode{LocalURL: server.URL}, homeRemoteFile{Path: "user/Documents/file.txt", Size: 4}, path, info)
	if err != nil || !equal || gets != 1 {
		t.Fatal("legacy metadata-only shortcut used", equal, err, gets)
	}
}

func TestHomeUploadHashReceiptMismatchFails(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0600)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			io.WriteString(w, "[]")
			return
		}
		io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Warden-SHA256", homeTestDigest([]byte("wrong")))
		w.WriteHeader(204)
	}))
	defer server.Close()
	r, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client())
	if err == nil || r.Uploaded != 0 || r.Failed != 1 {
		t.Fatalf("false success receipt: %+v %v", r, err)
	}
}
