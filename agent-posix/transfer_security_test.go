package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileTransferRejectsSymlinkEscape(t *testing.T) {
	inside := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("must remain unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(inside, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	if code, _, err := filePush(map[string]interface{}{"path": filepath.Join(link, "warden-test"), "content_b64": base64.StdEncoding.EncodeToString([]byte("changed"))}); err == nil || code == 0 {
		t.Fatal("escaped write accepted")
	}
	if _, err := zipDirectory(inside, 1024); err != nil {
		t.Fatal(err)
	}
}
func TestTransferReadRejectsOutsideRootAndOversizedFiles(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(directory, "outside")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	if code, _, err := filePull("no-network", map[string]interface{}{"path": link}); err == nil || code == 0 {
		t.Fatal("escaped read accepted")
	}
	huge := filepath.Join(directory, "large")
	file, err := os.Create(huge)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate((8 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if code, _, err := filePull("no-network", map[string]interface{}{"path": huge}); err == nil || code == 0 {
		t.Fatal("oversized read accepted")
	}
}
func TestArchiveDoesNotSilentlyTruncateCompressibleFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "file"), []byte(strings.Repeat("x", 2048)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := zipDirectory(directory, 1024); err == nil {
		t.Fatal("oversized uncompressed file accepted")
	}
	raw, err := zipDirectory(directory, 4096)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(reader.File) != 1 || reader.File[0].UncompressedSize64 != 2048 {
		t.Fatal("archive content truncated")
	}
}
