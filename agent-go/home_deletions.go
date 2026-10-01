package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type homeSyncState struct {
	Initialized bool              `json:"initialized"`
	Version     int               `json:"version"`
	Files       map[string]string `json:"files"`
	Deleted     map[string]string `json:"deleted,omitempty"`
	Conflicts map[string]homeConflict `json:"conflicts,omitempty"`
	LastPrompt  int64             `json:"last_prompt"`
}

var homeMappingLocks sync.Map

func syncHomeMappingTracked(space homeSpace, node homeNode, m homeMapping, username, root string, client *http.Client, observer ...func(homeSyncReport)) (homeSyncReport, error) {
	sum := sha256.Sum256([]byte(space.ID + "\x00" + space.Prefix + "\x00" + m.Target + "\x00" + strings.ToLower(root)))
	path := filepath.Join(dataDir, "home-sync-"+hex.EncodeToString(sum[:])+".state")
	value, _ := homeMappingLocks.LoadOrStore(path, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	state := homeSyncState{Version: 1, Files: map[string]string{}}
	raw, err := os.ReadFile(path)
	if err == nil {
		plain, err := decryptDPAPI(raw)
		if err != nil {
			return homeSyncReport{}, fmt.Errorf("read deletion history: %w", err)
		}
		if json.Unmarshal(plain, &state) != nil || state.Version != 1 || state.Files == nil {
			return homeSyncReport{}, errors.New("invalid Home deletion history; sync stopped")
		}
	} else if !os.IsNotExist(err) {
		return homeSyncReport{}, err
	}
	report, syncErr := syncHomeMappingFilesTracked(space, node, m, root, client, &state, func(paths []string) int {
		return confirmHomeEndpointDeletions(username, space.Name, paths)
	}, observer...)
	plain, err := json.Marshal(state)
	if err == nil {
		raw, err = encryptDPAPI(plain, "Warden Home sync history")
	}
	if err == nil {
		var temporary *os.File
		temporary, err = os.CreateTemp(dataDir, ".home-history-")
		if err == nil {
			name := temporary.Name()
			defer os.Remove(name)
			_, err = temporary.Write(raw)
			closeErr := temporary.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = os.Rename(name, path)
			}
		}
	}
	if err != nil {
		report.record(space.Name, m.Target, "history", "failed", 0, err)
		return report, fmt.Errorf("save deletion history: %w", err)
	}
	return report, syncErr
}

// 0 explicitly confirms cloud deletion, 1 explicitly restores, 2 defers.
func confirmHomeEndpointDeletions(username, space string, paths []string) int {
	token, err := activeUserPrimaryToken(username)
	if err != nil {
		return 2
	}
	exe, err := os.Executable()
	if err != nil {
		token.Close()
		return 2
	}
	var names []string
	for i, path := range paths {
		if i == 50 {
			break
		}
		names = append(names, boundedHomeReportText(path, 180))
	}
	content := fmt.Sprintf("%d Home files are missing from %s on this device. Did you intentionally delete them?\n\nOn a new or reset device, choose Restore files. Choose Delete from Home ONLY if you intentionally deleted these files.\n\nDelete from Home: remove these files from active Home storage and propagate the deletion. Other endpoints retain recoverable copies.\nRestore files: download Home's copies again.\nClose this window to decide later; missing files will NOT be downloaded.\n\n%s", len(paths), boundedHomeReportText(space, 100), strings.Join(names, "\n"))
	if len(paths) > len(names) {
		content += fmt.Sprintf("\n…and %d more files.", len(paths)-len(names))
	}
	helper, err := createInteractiveProcess(token, `winsta0\default`, exe, []string{"--home-deletion-confirm", content})
	if err != nil {
		return 2
	}
	if code, done := helper.wait(60 * time.Second); done {
		if code == 0 || code == 1 {
			return int(code)
		}
		return 2
	}
	helper.terminate(2 * time.Second)
	return 2
}

func listHomeFilesTracked(client *http.Client, node homeNode, prefix string) ([]homeRemoteFile, bool, error) {
    files,deletion,_,err:=listHomeFilesFeatures(client,node,prefix)
    return files,deletion,err
}

func listHomeFilesFeatures(client *http.Client, node homeNode, prefix string) ([]homeRemoteFile, bool, bool, error) {
	req, err := http.NewRequest(http.MethodGet, homeNodeURL(node)+"/v1/list?include_directories=1&include_deletions=1&path="+url.QueryEscape(prefix), nil)
	if err != nil {
        return nil, false, false, err
	}
	req.Header.Set("Authorization", "Bearer "+node.Grant)
	resp, err := client.Do(req)
	if err != nil {
        return nil, false, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
        return nil, false, false, fmt.Errorf("home list HTTP %d", resp.StatusCode)
	}
	var files []homeRemoteFile
	err = json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&files)
    return files, resp.Header.Get("X-Warden-Deletion-Tracking") == "1", resp.Header.Get("X-Warden-Conditional-Writes")=="1", err
}

func processHomeDeletions(space homeSpace, node homeNode, root, remoteRoot string, client *http.Client, remote []homeRemoteFile, state *homeSyncState, supported bool, confirm func([]string) int, report *homeSyncReport) map[string]bool {
	blocked := map[string]bool{}
	if state != nil && state.Deleted == nil {
		state.Deleted = map[string]string{}
	}
	var candidates []homeRemoteFile
	for _, f := range remote {
		if f.IsDir || !strings.HasPrefix(f.Path, remoteRoot+"/") {
			continue
		}
		rel := strings.TrimPrefix(f.Path, remoteRoot+"/")
		clean, err := cleanHomePart(rel)
		if err != nil {
			continue
		} // normal download validation reports this
		local := filepath.Join(root, filepath.FromSlash(clean))
		if err := validateHomeLocalPath(root, local); err != nil {
			blocked[f.Path] = true
			report.record(space.Name, rel, "delete", "failed", 0, err)
			continue
		}
		info, statErr := os.Stat(local)
		if f.Deleted {
			blocked[f.Path] = true
			version := fmt.Sprintf("%s:%d", f.SHA256, f.ModTime)
			if os.IsNotExist(statErr) {
				if state != nil {
					delete(state.Files, f.Path)
					state.Deleted[f.Path] = version
				}
				continue
			}
			if statErr != nil {
				report.record(space.Name, rel, "delete", "failed", 0, statErr)
				continue
			}
			// A file created AFTER this device observed/applied the deletion is
			// an intentional re-add. No popup; send a conditional upload token.
			if state != nil && state.Deleted[f.Path] == version && info.Mode().IsRegular() && node.Writable && space.AccessMode != "read" && space.SyncMode != "download" {
				delete(blocked, f.Path)
				continue
			}
			// Never erase locally modified/new content because another device
			// deleted an earlier version. Keep it and suppress its stale upload.
			if !info.Mode().IsRegular() {
				report.record(space.Name, rel, "delete", "skipped", 0, errors.New("deleted remote path has non-file local content"))
				continue
			}
			digest, err := localHomeDigest(local)
			if err != nil || !strings.EqualFold(digest, f.SHA256) {
				report.record(space.Name, rel, "delete", "skipped", 0, errors.New("remote file deleted; modified local copy retained, not uploaded"))
				continue
			}
			recoveryRoot := filepath.Join(filepath.Dir(root), "Warden Home Recovered")
			recovery := filepath.Join(recoveryRoot, fmt.Sprintf("%d-%x", time.Now().UnixNano(), sha256.Sum256([]byte(space.ID+remoteRoot))), filepath.FromSlash(clean))
			if err := validateHomeLocalPath(filepath.Dir(root), recovery); err == nil {
				err = os.MkdirAll(filepath.Dir(recovery), 0700)
				if err == nil {
					err = os.Rename(local, recovery)
				}
				if err != nil {
					report.record(space.Name, rel, "delete", "failed", 0, err)
					continue
				}
			} else {
				report.record(space.Name, rel, "delete", "failed", 0, err)
				continue
			}
			if state != nil {
				delete(state.Files, f.Path)
				state.Deleted[f.Path] = version
			}
			report.record(space.Name, rel, "delete", "deleted", 0, nil)
			continue
		}
		if state != nil {
			delete(state.Deleted, f.Path)
		}
		if state == nil || !os.IsNotExist(statErr) || state.Files[f.Path] == "" {
			continue
		}
		// A read-only/download-only mapping cannot delete Home content.
		if space.AccessMode == "read" || space.SyncMode == "download" {
			continue
		}
		blocked[f.Path] = true
		if !node.Writable {
			report.record(space.Name, rel, "delete", "skipped", 0, errors.New("deletion pending; connect to the writable Home Node to confirm"))
		} else if !supported {
			report.record(space.Name, rel, "delete", "skipped", 0, errors.New("deletion pending; upgrade Home Node for safe deletion confirmation"))
		} else if !strings.EqualFold(state.Files[f.Path], f.SHA256) {
			report.record(space.Name, rel, "delete", "skipped", 0, errors.New("Home copy changed since last sync; deletion paused to protect newer content"))
		} else {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return blocked
	}
	decision := 2
	if confirm != nil && time.Now().Unix()-state.LastPrompt >= 15*60 {
		names := make([]string, 0, len(candidates))
		for _, f := range candidates {
			names = append(names, strings.TrimPrefix(f.Path, remoteRoot+"/"))
		}
		state.LastPrompt = time.Now().Unix()
		decision = confirm(names)
	}
	if decision == 0 || decision == 1 {
		state.LastPrompt = 0
	}
	for _, f := range candidates {
		rel := strings.TrimPrefix(f.Path, remoteRoot+"/")
		if decision == 1 {
			delete(blocked, f.Path)
			delete(state.Files, f.Path) // explicitly restore; do not re-prompt
			continue
		}
		if decision != 0 {
			report.record(space.Name, rel, "delete", "skipped", 0, errors.New("deletion awaiting your confirmation; file not restored"))
			continue
		}
		// Re-check existence immediately before changing Home storage.
		local := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Lstat(local); !os.IsNotExist(err) {
			report.record(space.Name, rel, "delete", "skipped", 0, errors.New("local file reappeared; deletion cancelled"))
			continue
		}
		deletionVersion := ""
		req, err := http.NewRequest(http.MethodDelete, homeNodeURL(node)+"/v1/file?path="+url.QueryEscape(f.Path), nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+node.Grant)
			req.Header.Set("If-Match", "\""+f.SHA256+"\"")
			var resp *http.Response
			resp, err = client.Do(req)
			if err == nil {
				deletionVersion = resp.Header.Get("X-Warden-Deletion-Version")
				io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if resp.StatusCode != 204 {
					err = fmt.Errorf("home deletion HTTP %d; remote file may have changed", resp.StatusCode)
				}
			}
		}
		if err != nil {
			report.record(space.Name, rel, "delete", "failed", 0, err)
		} else {
			delete(state.Files, f.Path)
			if strings.HasPrefix(deletionVersion, f.SHA256+":") {
				state.Deleted[f.Path] = deletionVersion
			}
			report.record(space.Name, rel, "delete", "deleted", 0, nil)
		}
	}
	return blocked
}

func localHomeDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), err
}
