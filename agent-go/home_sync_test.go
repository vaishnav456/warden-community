package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHomeTransfersReportAcknowledgedFilesAndBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "send.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	var received string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/receive.txt", Size: 7, ModTime: 1234567}})
			return
		}
		if r.Method == http.MethodGet {
			io.WriteString(w, "welcome")
			return
		}
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	report, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if report.Uploaded != 1 || report.UploadedBytes != 5 || report.Downloaded != 1 || report.DownloadedBytes != 7 || received != "hello" {
		t.Fatalf("incorrect transfer receipt: %+v", report)
	}
	got, err := os.ReadFile(filepath.Join(root, "receive.txt"))
	if err != nil || string(got) != "welcome" {
		t.Fatalf("download missing: %q %v", got, err)
	}
}

func TestHomeEmptyDownloadIsACompletedFile(t *testing.T) {
	root := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/empty.txt", Size: 0, ModTime: 1234567}})
		}
	}))
	defer server.Close()
	report, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", SyncMode: "download", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL}, homeMapping{Target: "Documents"}, root, server.Client())
	if err != nil || report.Downloaded != 1 || report.DownloadedBytes != 0 {
		t.Fatalf("empty file receipt missing: %+v %v", report, err)
	}
	info, statErr := os.Stat(filepath.Join(root, "empty.txt"))
	if statErr != nil || info.Size() != 0 {
		t.Fatalf("empty file missing: %v", statErr)
	}
}

func TestHomeTruncatedDownloadFailsAndPreservesExistingFile(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "document.txt")
	if err := os.WriteFile(dst, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/document.txt", Size: 8, ModTime: 1234567}})
			return
		}
		io.WriteString(w, "short")
	}))
	defer server.Close()
	report, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", AccessMode: "read", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL}, homeMapping{Target: "Documents"}, root, server.Client())
	if err == nil || report.Failed != 1 || report.Downloaded != 0 {
		t.Fatalf("truncated file reported as success: %+v, %v", report, err)
	}
	got, readErr := os.ReadFile(dst)
	if readErr != nil || string(got) != "existing" {
		t.Fatalf("existing file was replaced: %q %v", got, readErr)
	}
	matches, _ := filepath.Glob(filepath.Join(root, ".warden-home-*"))
	if len(matches) != 0 {
		t.Fatalf("temporary download left behind: %v", matches)
	}
}

func TestHomeDownloadHTTPFailureIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/denied.txt", Size: 4, ModTime: 1234567}})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	report, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", SyncMode: "download", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL}, homeMapping{Target: "Documents"}, t.TempDir(), server.Client())
	if err == nil || report.Failed != 1 || !strings.Contains(err.Error(), "403") {
		t.Fatalf("download HTTP failure hidden: %+v %v", report, err)
	}
}

func TestHomeUploadRejectionAndSizeLimitCannotReportSuccess(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "denied.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte("too large"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			io.WriteString(w, "[]")
			return
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInsufficientStorage)
	}))
	defer server.Close()
	report, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", SyncMode: "upload", MaxFileBytes: 5}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client())
	if err == nil || report.Uploaded != 0 || report.Failed != 1 || report.Skipped != 1 {
		t.Fatalf("incomplete upload reported as success: %+v %v", report, err)
	}
}

func TestHomeUnchangedFileIsCountedOnce(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "same.txt")
	if err := os.WriteFile(dst, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dst, time.Unix(1234567, 0), time.Unix(1234567, 0)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/list" {
			t.Error("unchanged file transferred")
		}
		json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/same.txt", Size: 4, ModTime: 1234567, SHA256: homeTestDigest([]byte("same"))}})
	}))
	defer server.Close()
	report, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client())
	if err != nil || report.Unchanged != 1 || report.Uploaded+report.Downloaded != 0 {
		t.Fatalf("incorrect unchanged result: %+v %v", report, err)
	}
}

func TestHomeReportBoundsDetailsAndRetainsLateFailures(t *testing.T) {
	var report homeSyncReport
	for i := 0; i < homeReportDetailLimit+5; i++ {
		report.record("Home", "ok.txt", "upload", "uploaded", 2, nil)
	}
	report.record("Home", "failed.txt", "download", "failed", 0, errors.New("disk full"))
	if len(report.Files) != homeReportDetailLimit || report.OmittedDetails != 6 || report.UploadedBytes != 210 || report.Failed != 1 {
		t.Fatalf("unbounded or incorrect report: %+v", report)
	}
	if !strings.Contains(report.transferError().Error(), "disk full") {
		t.Fatal("late failure omitted")
	}
}
