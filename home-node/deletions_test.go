package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"testing"
)

func TestHomeDeletionMarkersAreConditionalAuthenticatedAndPreventResurrection(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	path := "homes/alice/file.txt"
	data := []byte("hello")
	if err := writeFile(path, bytes.NewReader(data), 123, 1024); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if status, err := confirmHomeDeletion(path, "wrong"); err == nil || status != 412 {
		t.Fatal("changed file deleted", status, err)
	}
	if status, err := confirmHomeDeletion(path, digest); err != nil || status != 204 {
		t.Fatal(status, err)
	}
	entries, err := listStoredFiles("homes/alice")
	if err != nil || len(entries) != 0 {
		t.Fatal("deleted file visible", entries, err)
	}
	entries, err = appendHomeDeletions("homes/alice", entries)
	if err != nil || len(entries) != 1 || !entries[0].Deleted || entries[0].SHA256 != digest {
		t.Fatal(entries, err)
	}
	status, err := storeAuthorizedFile(path, bytes.NewReader(data), 124, grant{Prefix: "homes/alice", MaxFileBytes: 1024})
	if status != http.StatusConflict || err == nil {
		t.Fatal("stale upload resurrected deletion", status, err)
	}
	if status, err := confirmHomeDeletion(path, digest); err != nil || status != 204 {
		t.Fatal("retry not idempotent", status, err)
	}
	stored, _, _ := pathsFor(path)
	if _, err := os.Stat(stored); err != nil {
		t.Fatal("encrypted recovery data lost", err)
	}
	raw, _ := os.ReadFile(stored + ".deleted")
	if bytes.Contains(raw, []byte(digest)) {
		t.Fatal("deletion metadata stored in plaintext")
	}
	raw[len(raw)-1] ^= 1
	os.WriteFile(stored+".deleted", raw, 0600)
	if _, err := readHomeDeletion(path); err == nil {
		t.Fatal("tampered deletion accepted")
	}
	if _, err := listStoredFiles("homes/alice"); err == nil {
		t.Fatal("corrupt marker ignored")
	}
}
