package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"runtime"
	"testing"
	"time"
)

func signedManagedUpdateForTest(t *testing.T, version string) managedUpdate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.NodeID = "node-test"
	pub = publicKey
	update := managedUpdate{
		NodeID:      cfg.NodeID,
		Version:     version,
		Platform:    runtime.GOOS + "-" + runtime.GOARCH,
		DownloadURL: "https://warden.example/api/home-node/update/" + runtime.GOOS + "-" + runtime.GOARCH,
		SHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssuedAt:    time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
	}
	message, err := managedUpdateCanonical(update)
	if err != nil {
		t.Fatal(err)
	}
	update.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	return update
}

func TestManagedUpdateRejectsTamperingAndDowngrade(t *testing.T) {
	update := signedManagedUpdateForTest(t, "1.2.0")
	if err := verifyManagedUpdate(update, false); err != nil {
		t.Fatalf("valid update rejected: %v", err)
	}
	tampered := update
	tampered.DownloadURL += "?different=true"
	if err := verifyManagedUpdate(tampered, false); err == nil {
		t.Fatal("tampered update was accepted")
	}
	downgrade := signedManagedUpdateForTest(t, "1.0.9")
	if err := verifyManagedUpdate(downgrade, false); err == nil {
		t.Fatal("downgrade was accepted")
	}
}

func TestManagedUpdateAllowsEqualVersionOnlyForApplyHelper(t *testing.T) {
	update := signedManagedUpdateForTest(t, homeNodeVersion)
	if err := verifyManagedUpdate(update, false); err == nil {
		t.Fatal("normal staging accepted an equal-version replay")
	}
	if err := verifyManagedUpdate(update, true); err != nil {
		t.Fatalf("privileged apply helper rejected the verified staged version: %v", err)
	}
}
