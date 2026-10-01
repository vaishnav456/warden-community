package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupBackupTest(t *testing.T) {
	t.Helper()
	previous := cfg
	previousKey := encryptionKeyID
	t.Cleanup(func() { cfg = previous; encryptionKeyID = previousKey })
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	cfg.BackupRoot = filepath.Join(t.TempDir(), "snapshots")
	cfg.BackupMaxBytes = 64 * 1024 * 1024
	cfg.StorageClusterID = ""
	encryptionKeyID = strings.Repeat("a", 64)
}
func TestIndependentBackupEncryptedRestoreAndEmptyFolders(t *testing.T) {
	setupBackupTest(t)
	rel := "homes/alice/Documents/report.txt"
	if _, err := storeAuthorizedFile(rel, bytes.NewBufferString("private content"), 123, grant{Prefix: "homes/alice", MaxFileBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(cfg.Root, "homes/alice/Documents/empty"), 0700)
	os.WriteFile(filepath.Join(cfg.Root, "warden-home.json"), []byte("SECRET KEY CONFIG"), 0600)
	result, err := createBackup()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(cfg.BackupRoot, result.SnapshotID)
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			raw, _ := os.ReadFile(path)
			if bytes.Contains(raw, []byte("private content")) || bytes.Contains(raw, []byte(rel)) || bytes.Contains(raw, []byte("SECRET KEY CONFIG")) {
				t.Fatal("backup exposed plaintext")
			}
		}
		return nil
	})
	manifest, err := readBackupManifest(directory, result.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range manifest.Objects {
		if object.Path == "warden-home.json" {
			t.Fatal("backup copied protected configuration")
		}
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err = restoreBackup(result.SnapshotID, target); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(target, "homes/alice/Documents/empty")); err != nil {
		t.Fatal("empty folder lost", err)
	}
	file, err := os.Open(filepath.Join(target, rel+".whome"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var plain bytes.Buffer
	if err = decryptStreamForPath(&plain, file, rel); err != nil || plain.String() != "private content" {
		t.Fatal("restore did not recover content", err)
	}
	if _, err = restoreBackup(result.SnapshotID, cfg.Root); err == nil {
		t.Fatal("active store overwritten")
	}
	if _, err = restoreBackup(result.SnapshotID, target); err == nil {
		t.Fatal("existing restore overwritten")
	}
}

func TestBackupSourcePinsOldDataAndMetadataWithoutCopyLock(t *testing.T) {
	setupBackupTest(t)
	rel := "homes/alice/Documents/pinned.txt"
	if _, err := storeAuthorizedFile(rel, bytes.NewBufferString("before"), 1, grant{Prefix: "homes/alice", MaxFileBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	storageMu.Lock()
	snapshot, err := captureBackupSource()
	storageMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(snapshot)
	if !storageMu.TryLock() {
		t.Fatal("capture retained storage lock")
	}
	storageMu.Unlock()
	if _, err := storeAuthorizedFile(rel, bytes.NewBufferString("after!"), 2, grant{Prefix: "homes/alice", MaxFileBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(filepath.Join(snapshot, rel+".whome"))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	err = decryptStreamForPath(&plain, src, rel)
	src.Close()
	if err != nil || plain.String() != "before" {
		t.Fatal("snapshot changed after live update", err)
	}
	// Metadata authentication uses the canonical active path; its bytes must stay pinned.
	raw, err := os.ReadFile(filepath.Join(snapshot, rel+".whome.meta"))
	if err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(filepath.Join(cfg.Root, rel+".whome.meta"))
	if err != nil || bytes.Equal(raw, live) {
        t.Fatal("snapshot metadata changed in place", err)
	}
}
func TestBackupTamperQuotaAndInvalidDestination(t *testing.T) {
	setupBackupTest(t)
	rel := "homes/alice/file.txt"
	storeAuthorizedFile(rel, bytes.NewBufferString("content"), 1, grant{Prefix: "homes/alice", MaxFileBytes: 1024})
	result, err := createBackup()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readBackupManifest(filepath.Join(cfg.BackupRoot, result.SnapshotID), result.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.BackupRoot, result.SnapshotID, manifest.Objects[0].ID+".blob")
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 1
	os.WriteFile(path, raw, 0600)
	if _, err = verifyBackup(result.SnapshotID); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
	target := filepath.Join(t.TempDir(), "must-not-exist")
	if _, err = restoreBackup(result.SnapshotID, target); err == nil {
		t.Fatal("tampered restore accepted")
	}
	if _, err = os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("failed authentication created recovery data")
	}
	cfg.BackupMaxBytes = 1
	if _, err = createBackup(); err == nil {
		t.Fatal("backup quota ignored")
	}
	cfg.BackupRoot = filepath.Join(cfg.Root, "unsafe")
	if _, err = createBackup(); err == nil {
		t.Fatal("nested backup accepted")
	}
	for _, id := range []string{"../outside", "", strings.Repeat("a", 33)} {
		if _, err = verifyBackup(id); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
	}
}
func TestBackupRejectsSymlinksAndCorruptedSource(t *testing.T) {
	setupBackupTest(t)
	os.WriteFile(filepath.Join(cfg.Root, "broken.whome"), []byte("not authenticated"), 0600)
	if _, err := createBackup(); err == nil {
		t.Fatal("corrupted encrypted source accepted")
	}
	os.Remove(filepath.Join(cfg.Root, "broken.whome"))
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(cfg.Root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := createBackup(); err == nil {
		t.Fatal("source symlink accepted")
	}
	os.Remove(filepath.Join(cfg.Root, "link"))
	cfg.BackupRoot = filepath.Join(t.TempDir(), "link")
	os.Symlink(outside, cfg.BackupRoot)
	if _, err := createBackup(); err == nil {
		t.Fatal("backup destination symlink accepted")
	}
}
