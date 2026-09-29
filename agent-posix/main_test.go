package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyEnrollmentResponseBindsNonceAndCredentials(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]interface{}{
		"api_key": "secret", "endpoint_id": "endpoint", "company_id": "company",
		"branch_id": nil, "client_cert_pem": "certificate", "enrollment_nonce": "nonce",
		"server_ed25519_pubkey": base64.StdEncoding.EncodeToString(pub),
	}
	proof, _ := json.Marshal(response)
	response["enrollment_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, proof))
	if err := verifyEnrollmentResponse(response, base64.StdEncoding.EncodeToString(pub), "nonce"); err != nil {
		t.Fatalf("valid enrollment proof rejected: %v", err)
	}
	response["api_key"] = "substituted"
	if err := verifyEnrollmentResponse(response, base64.StdEncoding.EncodeToString(pub), "nonce"); err == nil {
		t.Fatal("tampered enrollment credential was accepted")
	}
}

func resetReplayStoreForTest(t *testing.T) {
	t.Helper()
	replayMu.Lock()
	replayPath = filepath.Join(t.TempDir(), "replay-state.json")
	replays = replayStore{
		Nonces: map[string]replayEntry{}, Jobs: map[string]completedJob{},
		PendingReports: map[string]completedJob{},
	}
	replayMu.Unlock()
}

func TestNonceIsConsumedDurably(t *testing.T) {
	resetReplayStoreForTest(t)
	if err := checkAndConsumeNonce("nonce-1", time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatalf("first nonce use failed: %v", err)
	}
	if err := checkAndConsumeNonce("nonce-1", time.Now().Add(time.Minute).Unix()); err == nil {
		t.Fatal("replayed nonce was accepted")
	}

	replayMu.Lock()
	replays = replayStore{}
	replayMu.Unlock()
	if err := initReplayStore(); err != nil {
		t.Fatalf("reload replay store: %v", err)
	}
	if err := checkAndConsumeNonce("nonce-1", time.Now().Add(time.Minute).Unix()); err == nil {
		t.Fatal("replayed nonce was accepted after restart")
	}
}

func TestCompletedJobRemainsPendingUntilAcknowledged(t *testing.T) {
	resetReplayStoreForTest(t)
	result := completedJob{Status: "completed", ExitCode: 0, LogOutput: "done"}
	if err := recordCompletedJob("job-1", result); err != nil {
		t.Fatalf("record completed job: %v", err)
	}
	if _, ok := pendingJobReports()["job-1"]; !ok {
		t.Fatal("completed result was not queued for delivery")
	}
	if err := acknowledgeJobReport("job-1"); err != nil {
		t.Fatalf("acknowledge result: %v", err)
	}
	if _, ok := pendingJobReports()["job-1"]; ok {
		t.Fatal("acknowledged result remained in outbox")
	}
	if saved, ok := getCompletedJob("job-1"); !ok || saved.LogOutput != "done" {
		t.Fatal("job execution record was lost after report acknowledgement")
	}
}

func TestZipDirectoryPreservesRelativeFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "report.txt"), []byte("warden"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := zipDirectory(root, 1<<20)
	if err != nil {
		t.Fatalf("zip directory: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	found := false
	for _, f := range zr.File {
		if f.Name == "nested/report.txt" {
			found = true
		}
	}
	if !found {
		t.Fatal("archive did not contain the nested file")
	}
}

func TestElevationExpiryIsDurableAndBounded(t *testing.T) {
	elevationsPath = filepath.Join(t.TempDir(), "elevations.json")
	if err := recordElevationExpiry("alex", 60); err != nil {
		t.Fatalf("record elevation: %v", err)
	}
	if expiry := loadElevations()["alex"]; expiry <= time.Now().Unix() {
		t.Fatal("elevation expiry was not stored in the future")
	}
	if err := recordElevationExpiry("alex", 0); err == nil {
		t.Fatal("zero-duration elevation was accepted")
	}
	if err := recordElevationExpiry("alex", 1441); err == nil {
		t.Fatal("overlong elevation was accepted")
	}
}
