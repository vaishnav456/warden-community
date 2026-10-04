package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateCopyDoesNotFollowDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	source, target, link := filepath.Join(dir, "source"), filepath.Join(dir, "target"), filepath.Join(dir, "backup")
	if err := os.WriteFile(source, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable")
	}
	if err := copyFileExact(source, link, 0755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "unchanged" {
		t.Fatalf("symlink target overwritten: %s %v", raw, err)
	}
	raw, err = os.ReadFile(link)
	if err != nil || string(raw) != "replacement" {
		t.Fatalf("replacement missing: %s %v", raw, err)
	}
}

func TestHomeControlClientDoesNotForwardCredentialOnRedirect(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	request, _ := http.NewRequest(http.MethodPost, source.URL, nil)
	request.Header.Set("X-Warden-Home-Key", "fake-audit-key")
	response, err := homeControlClient().Do(request)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || leaked {
		t.Fatal("control client followed redirect")
	}
}

func TestHomeRejectsUnsafeServerURL(t *testing.T) {
	for _, raw := range []string{"http://warden.example", "https://user:pass@warden.example", "https://warden.example?key=x", "https://warden.example#fragment", ""} {
		if validateHomeServerURL(raw) == nil {
			t.Fatalf("unsafe URL accepted: %q", raw)
		}
	}
	if err := validateHomeServerURL("https://community.example"); err != nil {
		t.Fatal(err)
	}
}
