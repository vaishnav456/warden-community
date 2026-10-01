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
)

func TestHomeDeletionRequiresExplicitChoiceAndNeverRestoresPendingFile(t *testing.T) {
	for _, decision := range []int{0, 1, 2} {
		t.Run(string(rune('0'+decision)), func(t *testing.T) {
			root := t.TempDir()
			path := "user/Documents/file.txt"
			digest := homeTestDigest([]byte("hello"))
			state := &homeSyncState{Version: 1, Files: map[string]string{path: digest}}
			deletes, downloads, prompts := 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/list" {
					w.Header().Set("X-Warden-Deletion-Tracking", "1")
					json.NewEncoder(w).Encode([]homeRemoteFile{{Path: path, Size: 5, ModTime: 123, SHA256: digest}})
					return
				}
				if r.Method == http.MethodDelete {
					deletes++
					if r.Header.Get("If-Match") != "\""+digest+"\"" {
						t.Error("unconditional deletion")
					}
					w.WriteHeader(204)
					return
				}
				downloads++
				io.WriteString(w, "hello")
			}))
			defer server.Close()
			report, err := syncHomeMappingFilesTracked(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client(), state, func(paths []string) int {
				prompts++
				if len(paths) != 1 || paths[0] != "file.txt" {
					t.Error(paths)
				}
				return decision
			})
			if prompts != 1 {
				t.Fatal("confirmation missing")
			}
			switch decision {
			case 0:
				if err != nil || deletes != 1 || downloads != 0 || report.Deleted != 1 {
					t.Fatal(report, err, deletes, downloads)
				}
			case 1:
				if err != nil || deletes != 0 || downloads != 1 || report.Downloaded != 1 {
					t.Fatal(report, err, deletes, downloads)
				}
			case 2:
				if err == nil || deletes != 0 || downloads != 0 || report.Skipped != 1 {
					t.Fatal(report, err, deletes, downloads)
				}
			}
		})
	}
}

func TestHomeDeletionPausesChangedContentOldNodesAndRaces(t *testing.T) {
	for _, kind := range []string{"changed", "old_node", "remote_race", "local_race"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := "user/Documents/file.txt"
			digest := homeTestDigest([]byte("hello"))
			state := &homeSyncState{Version: 1, Files: map[string]string{path: digest}}
			deletes, gets := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/list" {
					if kind != "old_node" {
						w.Header().Set("X-Warden-Deletion-Tracking", "1")
					}
					if kind == "changed" {
						digest = homeTestDigest([]byte("newer"))
					}
					json.NewEncoder(w).Encode([]homeRemoteFile{{Path: path, Size: 5, SHA256: digest}})
					return
				}
				if r.Method == http.MethodDelete {
					deletes++
					w.WriteHeader(412)
					return
				}
				gets++
				w.WriteHeader(500)
			}))
			defer server.Close()
			report, err := syncHomeMappingFilesTracked(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client(), state, func([]string) int {
				if kind == "local_race" {
					os.WriteFile(filepath.Join(root, "file.txt"), []byte("new local data"), 0600)
				}
				return 0
			})
			if err == nil || gets != 0 || report.Deleted != 0 {
				t.Fatal("unsafe deletion/restore", report, err, gets)
			}
			if kind == "remote_race" && deletes != 1 {
				t.Fatal("conditional delete not attempted")
			}
			if kind != "remote_race" && deletes != 0 {
				t.Fatal("unsafe delete attempted")
			}
		})
	}
}

func TestHomeTombstoneSuppressesUploadAndPreservesModifiedCopies(t *testing.T) {
	for _, content := range []string{"hello", "modified"} {
		root := t.TempDir()
		local := filepath.Join(root, "file.txt")
		os.WriteFile(local, []byte(content), 0600)
		state := &homeSyncState{Version: 1, Files: map[string]string{}}
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/list" {
				json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/file.txt", Size: 5, SHA256: homeTestDigest([]byte("hello")), Deleted: true}})
				return
			}
			requests++
			w.WriteHeader(500)
		}))
		report, err := syncHomeMappingFilesTracked(homeSpace{Name: "Home", ID: "s", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client(), state, nil)
		server.Close()
		if requests != 0 {
			t.Fatal("deleted file uploaded again")
		}
		data, readErr := os.ReadFile(local)
		if content == "hello" {
			if err != nil || !os.IsNotExist(readErr) || report.Deleted != 1 {
				t.Fatal(report, err, readErr)
			}
			recovered := filepath.Join(filepath.Dir(root), "Warden Home Recovered")
			found := false
			filepath.Walk(recovered, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.HasSuffix(path, "file.txt") {
					b, _ := os.ReadFile(path)
					if string(b) == "hello" {
						found = true
					}
				}
				return nil
			})
			if !found {
				t.Fatal("recoverable local copy missing")
			}
		} else if err == nil || readErr != nil || string(data) != content {
			t.Fatal("modified copy lost", report, err)
		}
	}
}

func TestHomeStateCapturesSuccessfulFilesBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(root, "file.txt")
	os.WriteFile(local, []byte("hello"), 0600)
	state := &homeSyncState{Version: 1, Files: map[string]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Warden-Deletion-Tracking", "1")
		json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/file.txt", Size: 5, SHA256: homeTestDigest([]byte("hello"))}})
	}))
	defer server.Close()
	_, err := syncHomeMappingFilesTracked(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client(), state, nil)
	if err != nil || state.Files["user/Documents/file.txt"] != homeTestDigest([]byte("hello")) {
		t.Fatal("baseline missing", state, err)
	}
}

func TestFirstTrackedSyncAsksBeforeRestoringPreviouslyMissingFiles(t *testing.T) {
	root := t.TempDir()
	state := &homeSyncState{Version: 1, Files: map[string]string{}}
	gets, prompts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/list" {
			w.Header().Set("X-Warden-Deletion-Tracking", "1")
			json.NewEncoder(w).Encode([]homeRemoteFile{{Path: "user/Documents/file.txt", Size: 5, SHA256: homeTestDigest([]byte("hello"))}})
			return
		}
		gets++
		io.WriteString(w, "hello")
	}))
	defer server.Close()
	report, err := syncHomeMappingFilesTracked(homeSpace{Name: "Home", Prefix: "user", MaxFileBytes: 1024}, homeNode{LocalURL: server.URL, Writable: true}, homeMapping{Target: "Documents"}, root, server.Client(), state, func([]string) int { prompts++; return 2 })
	if err == nil || prompts != 1 || gets != 0 || report.Skipped != 1 || !state.Initialized {
		t.Fatal(report, err, prompts, gets)
	}
}
