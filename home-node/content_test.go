package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestStoredContentHashIsAuthenticatedAndLegacyFilesRemainReadable(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	path := "homes/alice/document.txt"
	plain := []byte("content")
	if err := writeFile(path, bytes.NewReader(plain), 123, 1024); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	want := hex.EncodeToString(sum[:])
	_, metaPath, _ := pathsFor(path)
	m := loadMeta(metaPath)
	if !m.Valid || m.SHA256 != want {
		t.Fatal("plaintext digest missing", m)
	}
	entries, err := listStoredFiles("homes/alice")
	if err != nil || len(entries) != 1 || entries[0].SHA256 != want {
		t.Fatal("listing digest missing", entries, err)
	}
	original := m
	m.SHA256 = hex.EncodeToString(make([]byte, 32))
	raw, _ := json.Marshal(m)
	os.WriteFile(metaPath, raw, 0600)
	if loadMeta(metaPath).Valid {
		t.Fatal("tampered content hash accepted")
	}
	// Reproduce existing authenticated v2 metadata without a digest.
	m = original
	m.SHA256 = ""
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	tag := aead.Seal(nil, nonce, nil, metadataAAD(path, m.Size, m.ModTime))
	m.Auth = base64.RawURLEncoding.EncodeToString(append(nonce, tag...))
	raw, _ = json.Marshal(m)
	os.WriteFile(metaPath, raw, 0600)
	entries, err = listStoredFiles("homes/alice")
	if err != nil || len(entries) != 1 || entries[0].SHA256 != want {
		t.Fatal("legacy content digest missing", entries, err)
	}
}

func TestReplicaDigestMismatchPreservesPreviousFile(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	path := "homes/alice/file.txt"
	if err := writeFile(path, bytes.NewReader([]byte("previous")), 123, 1024); err != nil {
		t.Fatal(err)
	}
	if err := writeFileVerified(path, bytes.NewReader([]byte("incorrect")), 124, 1024, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("mismatched replica accepted")
	}
	data, _, _ := pathsFor(path)
	f, err := os.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var plain bytes.Buffer
	if err := decryptStreamForPath(io.Writer(&plain), f, path); err != nil || plain.String() != "previous" {
		t.Fatal("old replica lost", err, plain.String())
	}
}

func TestEmptyDirectoryProtocolIsAuthorizedAndBackwardCompatible(t *testing.T) {
	private := configureTestCrypto(t)
	cfg.Root = t.TempDir()
	token := testGrantWithLimits(t, private, "homes/alice", 1024, 0)
	request := func(path, grant string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/v1/directory?path="+path, nil)
		r.Header.Set("Authorization", "Bearer "+grant)
		w := httptest.NewRecorder()
		handleDirectory(w, r)
		return w
	}
	if w := request("homes/alice/nested/empty", token); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("homes/bob/empty", token); w.Code != 401 {
		t.Fatal("cross-user directory accepted", w.Code)
	}
	if w := request("homes/alice/another", ""); w.Code != 401 {
		t.Fatal("unsigned directory accepted", w.Code)
	}
	entries, err := listStoredEntries("homes/alice", true)
	if err != nil || len(entries) != 2 || !entries[0].IsDir || !entries[1].IsDir {
		t.Fatal("empty directory listing missing", entries, err)
	}
	files, err := listStoredFiles("homes/alice")
	if err != nil || len(files) != 0 {
		t.Fatal("old clients received directory entries", files, err)
	}
}
