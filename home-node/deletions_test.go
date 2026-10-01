package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	stored, meta, _ := pathsFor(path)
	for _, file := range []string{stored, meta} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatal("deleted contents still consume storage", file, err)
		}
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
	if _, err := appendHomeDeletions("homes/alice", nil); err == nil {
		t.Fatal("corrupt marker ignored")
	}
}

func TestHomeDeletionCleanupRepairsOldMarkersAndPreservesActiveFiles(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	deleted := "homes/alice/deleted.txt"
	live := "homes/alice/live.txt"
	content := []byte("old contents")
	for _, rel := range []string{deleted, live} {
		if err := writeFile(rel, bytes.NewReader(content), 123, 1024); err != nil {
			t.Fatal(err)
		}
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	stored, meta, _ := pathsFor(deleted)
	oldData, _ := os.ReadFile(stored)
	oldMeta, _ := os.ReadFile(meta)
	if err := writeHomeDeletion(deleted, homeDeletion{SHA256: digest, Size: int64(len(content)), DeletedAt: 123}); err != nil {
		t.Fatal(err)
	}
	// Reproduce the previous release's marker plus retained encrypted contents.
	os.WriteFile(stored, oldData, 0600)
	os.WriteFile(meta, oldMeta, 0600)
	if err := cleanupHomeDeletions("homes/alice"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stored, meta} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("old deletion contents not purged", path, err)
		}
	}
	liveData, _, _ := pathsFor(live)
	if _, err := os.Stat(liveData); err != nil {
		t.Fatal("active file removed", err)
	}
	if err := cleanupHomeDeletions("homes/alice"); err != nil {
		t.Fatal("cleanup not idempotent", err)
	}
	if deletion, err := readHomeDeletion(deleted); err != nil || deletion == nil {
		t.Fatal("anti-resurrection record lost", deletion, err)
	}
}

func TestHomeDeletionCleanupFailureIsRetriedAndCorruptMarkersNeverPurge(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	rel := "homes/alice/file.txt"
	content := []byte("hello")
	if err := writeFile(rel, bytes.NewReader(content), 123, 1024); err != nil {
		t.Fatal(err)
	}
	stored, meta, _ := pathsFor(rel)
	oldData, _ := os.ReadFile(stored)
	oldMeta, _ := os.ReadFile(meta)
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	if err := writeHomeDeletion(rel, homeDeletion{SHA256: digest, Size: 5, DeletedAt: 123}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(stored, oldData, 0600)
	os.Mkdir(meta, 0700)
	os.WriteFile(filepath.Join(meta, "keep"), []byte("not metadata"), 0600)
	if status, err := confirmHomeDeletion(rel, digest); status != 500 || err == nil {
		t.Fatal("failed cleanup acknowledged", status, err)
	}
	if _, err := os.Stat(stored); err != nil {
		t.Fatal("nonregular metadata not checked before purge", err)
	}
	os.Remove(filepath.Join(meta, "keep"))
	os.Remove(meta)
	if status, err := confirmHomeDeletion(rel, digest); status != 204 || err != nil {
		t.Fatal("cleanup retry failed", status, err)
	}
	os.WriteFile(stored, oldData, 0600)
	os.WriteFile(meta, oldMeta, 0600)
	raw, _ := os.ReadFile(stored + ".deleted")
	raw[len(raw)-1] ^= 1
	os.WriteFile(stored+".deleted", raw, 0600)
	if err := cleanupHomeDeletions("homes/alice"); err == nil {
		t.Fatal("unauthenticated marker accepted")
	}
	if _, err := os.Stat(stored); err != nil {
		t.Fatal("contents purged using corrupt marker", err)
	}
}

func TestHomeReaddRequiresCurrentDeletionVersionAndClearsMarkerAfterSuccess(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	rel := "homes/alice/file.txt"
	content := []byte("same contents")
	g := grant{Prefix: "homes/alice", MaxFileBytes: 1024}
	if err := writeFile(rel, bytes.NewReader(content), 123, 1024); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	if status, err := confirmHomeDeletion(rel, digest); status != 204 || err != nil {
		t.Fatal(status, err)
	}
	deletion, _ := readHomeDeletion(rel)
	for _, token := range []string{"", digest + ":1"} {
		if status, err := storeAuthorizedFileVerified(rel, bytes.NewReader(content), 124, g, "", token); status != 409 || err == nil {
			t.Fatal("stale upload accepted", status, err)
		}
	}
	version := homeDeletionVersion(deletion)
	if status, err := storeAuthorizedFileVerified(rel, bytes.NewReader(content), 124, g, "wrong", version); status != 500 || err == nil {
		t.Fatal("unverified re-add accepted", status, err)
	}
	if deletion, _ := readHomeDeletion(rel); deletion == nil {
		t.Fatal("failed upload cleared marker")
	}
	if status, err := storeAuthorizedFileVerified(rel, bytes.NewReader(content), 124, g, digest, version); status != 204 || err != nil {
		t.Fatal("same-content re-add failed", status, err)
	}
	if deletion, err := readHomeDeletion(rel); deletion != nil || err != nil {
		t.Fatal("successful re-add left marker", deletion, err)
	}
	entries, err := listStoredFiles("homes/alice")
	if err != nil || len(entries) != 1 || entries[0].SHA256 != digest {
		t.Fatal("re-added file unavailable", entries, err)
	}
	if status, err := confirmHomeDeletion(rel, digest); status != 204 || err != nil {
		t.Fatal(status, err)
	}
	if status, err := storeAuthorizedFileVerified(rel, bytes.NewReader(content), 125, g, "", version); status != 409 || err == nil {
		t.Fatal("earlier deletion version accepted", status, err)
	}
}
