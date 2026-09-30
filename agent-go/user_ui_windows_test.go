package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWardenApprovalFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		message    uint32
		id, source uintptr
		want       int
	}{
		{"deny", 0x111, 7, 1, 2},
		{"close", 0x10, 0, 0, 2},
		{"timeout", 0x113, 0, 0, 2},
		{"default enter", 0x111, 1, 0, 2},
		{"no affirmative control", 0x111, 6, 0, 2},
		{"explicit allow", 0x111, 6, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			currentWardenUI = &wardenUI{approval: true, result: 2}
			defer func() { currentWardenUI = nil }()
			wardenWindowProc(0, tc.message, tc.id, tc.source)
			if currentWardenUI.result != tc.want {
				t.Fatalf("result=%d want=%d", currentWardenUI.result, tc.want)
			}
		})
	}
}

func TestWardenNativeUIABIAndText(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		if unsafe.Sizeof(uiClass{}) != 80 || unsafe.Sizeof(uiMessage{}) != 48 || unsafe.Sizeof(uiPaint{}) != 72 {
			t.Fatal("Win32 structure alignment is incorrect")
		}
	}
	if got := windows.UTF16PtrToString(uiString("hello\x00visible")); got != "hello visible" {
		t.Fatal(got)
	}
	currentWardenUI = &wardenUI{transient: true}
	defer func() { currentWardenUI = nil }()
	if wardenWindowProc(0, 0x21, 0, 0) != 3 {
		t.Fatal("notification would activate the foreground window")
	}
}

func TestHomeSyncNoticesAreHonestAndQuiet(t *testing.T) {
	now := time.Now()
	r := homeSyncReport{Status: "completed", Uploaded: 2, Downloaded: 1, Unchanged: 4}
	title, body, severity := homeSyncNotice(r)
	if title != "Warden Home sync complete" || severity != "info" || !strings.Contains(body, "Incremental") {
		t.Fatal(title, body, severity)
	}
	previous := homeNoticeState{status: "completed", at: now.Add(-2 * time.Minute)}
	if !shouldShowHomeNotice(r, previous, now) {
		t.Fatal("changed files should notify")
	}
	r.Uploaded, r.Downloaded = 0, 0
	if shouldShowHomeNotice(r, previous, now) {
		t.Fatal("idle polls must not notify")
	}
	if !shouldShowHomeNotice(r, homeNoticeState{}, now) {
		t.Fatal("first successful sync should notify even when already up to date")
	}
	for _, failed := range []homeSyncReport{{Status: "failed"}, {Status: "completed", Failed: 1}, {Status: "completed", Skipped: 1}} {
		title, _, severity = homeSyncNotice(failed)
		if strings.Contains(title, "complete") || severity != "warning" {
			t.Fatal("false success notification")
		}
	}
	r.Status = "failed"
	if !shouldShowHomeNotice(r, previous, now) {
		t.Fatal("new failure should notify")
	}
	if shouldShowHomeNotice(r, homeNoticeState{status: "failed", at: now}, now) {
		t.Fatal("repeat failure should be throttled")
	}
}

func TestHomeSyncTransfersOnlyNewOrChangedFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "document.txt")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0)
	os.Chtimes(path, stamp, stamp)
	var remote []homeRemoteFile
	puts, gets := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			json.NewEncoder(w).Encode(remote)
			return
		}
		if r.Method == http.MethodPut {
			puts++
			data, _ := io.ReadAll(r.Body)
			info, _ := os.Stat(path)
			remote = []homeRemoteFile{{Path: "user/Documents/document.txt", Size: int64(len(data)), ModTime: info.ModTime().Unix(), SHA256: homeTestDigest(data)}}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		gets++
	}))
	defer server.Close()
	run := func() homeSyncReport {
		r, err := syncHomeMappingFiles(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := run(); r.Uploaded != 1 {
		t.Fatal("initial file was not uploaded", r)
	}
	if r := run(); r.Uploaded != 0 || r.Downloaded != 0 || r.Unchanged != 1 || puts != 1 || gets != 0 {
		t.Fatal("unchanged file was transferred again", r)
	}
	if err := os.WriteFile(path, []byte("changed contents"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, stamp.Add(time.Second), stamp.Add(time.Second))
	if r := run(); r.Uploaded != 1 || puts != 2 || gets != 0 {
		t.Fatal("changed file was not uploaded incrementally", r)
	}
}
