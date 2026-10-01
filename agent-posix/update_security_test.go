package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateRejectsDowngradesAndInvalidVersionsBeforeDownloading(t *testing.T) {
	for _, version := range []string{"1.0.0", agentVersion} {
		code, _, err := updateAgent(map[string]interface{}{"version": version})
		if code != 0 || err != nil {
			t.Fatalf("version %s: code=%d err=%v", version, code, err)
		}
	}
	for _, version := range []string{"", "+3.0.0", "3.0", "3.x.0", "3.0.0-beta", "999999999999999999999.0.0"} {
		code, _, err := updateAgent(map[string]interface{}{"version": version})
		if code == 0 || err == nil {
			t.Fatalf("accepted invalid version %q", version)
		}
	}
	comparison, err := compareAgentVersions("2.10.0", "2.9.99")
	if comparison != 1 || err != nil {
		t.Fatalf("numeric comparison failed: %d %v", comparison, err)
	}
}

func TestDownloadRejectsOriginChangesMissingHashesAndRedirects(t *testing.T) {
	oldConfig, oldClient, oldKey := cfg, httpClient, apiKey
	defer func() { cfg, httpClient, apiKey = oldConfig, oldClient, oldKey }()
	leaked := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	data := []byte("verified artifact")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	cfg.ServerURL = server.URL
	httpClient = server.Client()
	apiKey = "must-not-leak"
	destination := filepath.Join(t.TempDir(), "artifact")
	for _, candidate := range []string{
		target.URL, strings.Replace(server.URL, "https:", "http:", 1),
		server.URL + "#fragment", strings.Replace(server.URL, "https://", "https://user:pass@", 1),
	} {
		if err := download(candidate, destination, digest); err == nil {
			t.Fatalf("accepted %s", candidate)
		}
	}
	if err := download(server.URL, destination, ""); err == nil {
		t.Fatal("accepted missing hash")
	}
	if err := download(server.URL+"/redirect", destination, digest); err == nil {
		t.Fatal("followed update redirect")
	}
	if leaked {
		t.Fatal("agent credentials were sent to redirect target")
	}
	if err := download(server.URL, destination, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted wrong hash")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("failed download created destination")
	}
	if err := download(server.URL, destination, digest); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(destination)
	if err != nil || string(actual) != string(data) {
		t.Fatalf("verified download failed: %v", err)
	}
}
