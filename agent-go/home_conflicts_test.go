package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHomeConflictsPreserveBothAndRequireHashBoundChoice(t *testing.T) {
	for _, choice := range []string{"local", "home", "both"} {
		t.Run(choice, func(t *testing.T) {
			root := t.TempDir()
			rel := "user/Documents/file.txt"
			local := filepath.Join(root, "file.txt")
			os.WriteFile(local, []byte("local"), 0600)
			remoteData := []byte("remote")
			uploads, gets := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/list" {
					w.Header().Set("X-Warden-Conditional-Writes", "1")
					json.NewEncoder(w).Encode([]homeRemoteFile{{Path: rel, Size: int64(len(remoteData)), ModTime: 123, SHA256: homeTestDigest(remoteData)}})
					return
				}
				if r.Method == http.MethodPut {
					if r.URL.Query().Get("path") == rel && r.Header.Get("If-Match") != "\""+homeTestDigest(remoteData)+"\"" {
						t.Error("unconditional overwrite")
					}
					body, _ := io.ReadAll(r.Body)
					if r.URL.Query().Get("path") == rel {
						remoteData = body
					}
					uploads++
					w.Header().Set("X-Warden-SHA256", homeTestDigest(body))
					w.WriteHeader(204)
					return
				}
				gets++
				w.Write(remoteData)
			}))
			defer server.Close()
			state := &homeSyncState{Version: 1, Files: map[string]string{rel: homeTestDigest([]byte("baseline"))}}
			space := homeSpace{ID: "space-a", Name: "Home", Prefix: "user", MaxFileBytes: 1024}
			node := homeNode{LocalURL: server.URL, Writable: true}
			mapping := homeMapping{Target: "Documents"}
			run := func() homeSyncReport {
				r, _ := syncHomeMappingFilesTracked(space, node, mapping, root, server.Client(), state, func([]string) int { return 2 })
				return r
			}
			report := run()
			if uploads != 0 || gets != 1 || report.Skipped == 0 || len(state.Conflicts) != 1 {
				t.Fatal("conflict not paused", report, uploads, gets, state)
			}
			content, _ := os.ReadFile(local)
			if string(content) != "local" {
				t.Fatal("local overwritten")
			}
			copy := state.Conflicts[rel].ServerCopy
			content, _ = os.ReadFile(filepath.Join(root, copy))
			if string(content) != "remote" {
				t.Fatal("remote copy not preserved")
			}
			run()
			if gets != 1 || uploads != 0 {
				t.Fatal("repeated conflict duplicated or uploaded", gets, uploads)
			}
			space.Resolution = &homeResolution{Path: "Documents/file.txt", Choice: choice, LocalSHA: homeTestDigest([]byte("local")), RemoteSHA: homeTestDigest(remoteData)}
			report = run()
			if report.Failed != 0 || len(state.Conflicts) != 0 {
				t.Fatal("resolution failed", report, state)
			}
			content, _ = os.ReadFile(local)
			expected := "local"
			if choice == "home" {
				expected = "remote"
			}
			if string(content) != expected {
				t.Fatal("wrong chosen copy", string(content))
			}
			if choice == "home" && uploads != 0 {
				t.Fatal("Home choice uploaded original")
			}
		})
	}
}

func TestHomeConflictResolutionRejectsLegacyNodesAndStaleReview(t *testing.T) {
	for _, choice := range []string{"local", "both", "stale-review"} {
		t.Run(choice, func(t *testing.T) {
			root := t.TempDir()
			localSHA := homeTestDigest([]byte("local"))
			remoteSHA := homeTestDigest([]byte("remote"))
			os.WriteFile(filepath.Join(root, "file.txt"), []byte("local"), 0600)
			os.WriteFile(filepath.Join(root, "saved-copy"), []byte("remote"), 0600)
			state := &homeSyncState{
				Files: map[string]string{},
				Conflicts: map[string]homeConflict{"user/Documents/file.txt": {
					LocalSHA: localSHA, RemoteSHA: remoteSHA, ServerCopy: "saved-copy",
				}},
			}
			resolution := &homeResolution{Path: "Documents/file.txt", Choice: choice, LocalSHA: localSHA, RemoteSHA: remoteSHA}
			if choice == "stale-review" {
				resolution.Choice = "home"
				resolution.RemoteSHA = homeTestDigest([]byte("outdated"))
			}
			space := homeSpace{Prefix: "user", Resolution: resolution}
			remote := homeRemoteFile{Path: "user/Documents/file.txt", SHA256: remoteSHA}
			if _, err := prepareHomeConflict(space, homeNode{}, root, "file.txt", remote, localSHA, nil, state, &homeSyncReport{}); err == nil {
				t.Fatal("unsafe conflict choice was accepted")
			}
			for path, expected := range map[string]string{"file.txt": "local", "saved-copy": "remote"} {
				data, err := os.ReadFile(filepath.Join(root, path))
				if err != nil || string(data) != expected {
					t.Fatal("rejected resolution changed a preserved file", path, err)
				}
			}
			if len(state.Conflicts) != 1 {
				t.Fatal("rejected resolution discarded conflict state")
			}
		})
	}
}

func TestHomeReportFullCannotAnnotateAnotherReceipt(t *testing.T) {
	report := homeSyncReport{}
	for i := 0; i < homeReportDetailLimit; i++ {
		report.record("Home", "old", "upload", "uploaded", 1, nil)
	}
	if detail := report.record("Home", "new", "upload", "uploaded", 1, nil); detail != nil {
		t.Fatal("omitted receipt aliases previous file")
	}
	if report.Files[len(report.Files)-1].Verified {
		t.Fatal("previous receipt falsely verified")
	}
	detail := report.record("Home", "conflict", "conflict", "conflict", 0, nil)
	if detail == nil || detail.Path != "conflict" {
		t.Fatal("late conflict cannot be reviewed")
	}
	merged := homeSyncReport{}
	for i := 0; i < homeReportDetailLimit; i++ {
		merged.record("Home", "old", "upload", "uploaded", 1, nil)
	}
	merged.merge(report)
	found := false
	for _, file := range merged.Files {
		if file.Status == "conflict" {
			found = true
		}
	}
	if !found {
		t.Fatal("multi-folder merge hid conflict")
	}
}
