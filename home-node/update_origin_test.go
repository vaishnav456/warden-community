package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedDownloadStaysOnConfiguredServerAndRejectsRedirects(t *testing.T) {
	previous := cfg
	defer func() { cfg = previous }()
	leaked := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	// An origin rejection happens before networking, even when the foreign
	// server has a valid public certificate.
	cfg.WardenURL = "https://community.example"
	cfg.NodeKey = "must-not-leak"
	data := sha256.Sum256([]byte("artifact"))
	digest := hex.EncodeToString(data[:])
	for _, candidate := range []string{
		target.URL, "http://community.example/update", "https://other.example/update",
		"https://user:pass@community.example/update", "https://community.example/update#fragment",
	} {
		update := managedUpdate{DownloadURL: candidate, SHA256: digest}
		if err := downloadManagedUpdate(update, filepath.Join(t.TempDir(), "update")); err == nil {
			t.Fatalf("accepted foreign or unsafe update URL %s", candidate)
		}
	}
	if leaked {
		t.Fatal("Home key was sent to foreign server")
	}
	// Direct HTTPS redirects must be denied by the client. Use the server's
	// certificate as a temporary test root, never disable verification.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()
	cfg.WardenURL = server.URL
	oldTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	err := downloadManagedUpdate(managedUpdate{DownloadURL: server.URL, SHA256: digest}, filepath.Join(t.TempDir(), "update"))
	if err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("redirect was not refused: %v", err)
	}
	if leaked {
		t.Fatal("Home key leaked through a redirect")
	}
}
