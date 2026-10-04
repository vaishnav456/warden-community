//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeRequiresExistingProtectedUpdateIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership test runs in isolated Linux container")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := requireManagedUpdateTrust(path); err == nil || !strings.Contains(err.Error(), "trust-updates -config") {
		t.Fatalf("missing identity must give migration instructions: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("upgrade check must not bootstrap trust")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(updateTrustIdentity{"node-test", base64.StdEncoding.EncodeToString(public)})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedUpdateTrust(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedUpdateTrust(path); err == nil {
		t.Fatal("upgrade accepted service-writable identity")
	}
}

func TestUpdateIdentityRequiresProtectedOwnerAndPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership test runs in isolated Linux container")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(updateTrustIdentity{"node-test", base64.StdEncoding.EncodeToString(public)})
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpdateTrustIdentity(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpdateTrustIdentity(path); err == nil {
		t.Fatal("writable trust accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpdateTrustIdentity(path); err == nil {
		t.Fatal("service-owned trust accepted")
	}
}

func TestUpdateIdentityRejectsSymlinkAndWritableParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership test runs in isolated Linux container")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(updateTrustIdentity{"node-test", base64.StdEncoding.EncodeToString(public)})
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, raw, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "identity.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpdateTrustIdentity(link); err == nil {
		t.Fatal("symlink trust accepted")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpdateTrustIdentity(target); err == nil {
		t.Fatal("writable trust directory accepted")
	}
}
