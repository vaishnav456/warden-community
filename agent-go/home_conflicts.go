package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type homeConflict struct {
	LocalSHA   string `json:"local_sha"`
	RemoteSHA  string `json:"remote_sha"`
	ServerCopy string `json:"server_copy"`
}
type homeResolution struct {
	Path      string `json:"path"`
	Choice    string `json:"choice"`
	LocalSHA  string `json:"local_sha"`
	RemoteSHA string `json:"remote_sha"`
}

func recoverHomeFile(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("invalid conflict recovery path")
	}
	recovery := filepath.Join(filepath.Dir(root), "Warden Home Recovered", fmt.Sprint(time.Now().UnixNano()), rel)
	if err = validateHomeLocalPath(filepath.Dir(root), recovery); err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(recovery), 0700); err != nil {
		return "", err
	}
	if err = os.Rename(path, recovery); err != nil {
		return "", err
	}
	return recovery, nil
}

// Keep both actual versions, stop upload of the original and offer an explicit
// choice. Resolution is conditional on BOTH content hashes, never timestamps.
func prepareHomeConflict(space homeSpace, node homeNode, root, rel string, remote homeRemoteFile, localSHA string, client *http.Client, state *homeSyncState, report *homeSyncReport) (string, error) {
	if state.Conflicts == nil {
		state.Conflicts = map[string]homeConflict{}
	}
	conflict, exists := state.Conflicts[remote.Path]
	if !exists || conflict.LocalSHA != localSHA || conflict.RemoteSHA != remote.SHA256 {
		if exists {
			oldCopy := filepath.Join(root, filepath.FromSlash(conflict.ServerCopy))
			if err := validateHomeLocalPath(root, oldCopy); err != nil {
				return "", err
			}
			if _, err := os.Stat(oldCopy); err == nil {
				if _, err = recoverHomeFile(root, oldCopy); err != nil {
					return "", err
				}
			} else if !os.IsNotExist(err) {
				return "", err
			}
		}
		token := make([]byte, 8)
		if _, err := rand.Read(token); err != nil {
			return "", err
		}
		copyRel := rel + ".warden-conflict-remote-" + hex.EncodeToString(token)
		copyPath := filepath.Join(root, filepath.FromSlash(copyRel))
		if err := validateHomeLocalPath(root, copyPath); err != nil {
			return "", err
		}
		if _, err := downloadHomeFile(client, node, remote, copyPath, space.MaxFileBytes); err != nil {
			return "", err
		}
		conflict = homeConflict{LocalSHA: localSHA, RemoteSHA: remote.SHA256, ServerCopy: copyRel}
		state.Conflicts[remote.Path] = conflict
	}
	choice := ""
	if resolution := space.Resolution; resolution != nil && resolution.Path == strings.TrimSpace(strings.TrimPrefix(remote.Path, strings.Trim(space.Prefix, "/")+"/")) {
		if resolution.LocalSHA != localSHA || resolution.RemoteSHA != remote.SHA256 {
			return "", errors.New("conflict changed after review; refresh its result")
		}
		choice = resolution.Choice
	}
	serverCopy := filepath.Join(root, filepath.FromSlash(conflict.ServerCopy))
	if err := validateHomeLocalPath(root, serverCopy); err != nil {
		return "", err
	}
	copySHA, err := localHomeDigest(serverCopy)
	if err != nil || copySHA != remote.SHA256 {
		return "", errors.New("saved Home conflict copy changed; both versions retained")
	}
	if choice == "home" {
		original := filepath.Join(root, filepath.FromSlash(rel))
		backup, err := recoverHomeFile(root, original)
		if err != nil {
			return "", err
		}
		if err = os.Rename(serverCopy, original); err != nil {
			os.Rename(backup, original)
			return "", err
		}
		state.Files[remote.Path] = remote.SHA256
		delete(state.Conflicts, remote.Path)
		report.record(space.Name, rel, "resolve", "resolved", 0, nil)
		return "home", nil
	}
	if choice == "local" || choice == "both" {
		if !node.ConditionalWrites {
			return "", errors.New("update the Home Node to support safe conditional conflict resolution; both versions retained")
		}
		return choice, nil
	}
	if choice != "" {
		return "", errors.New("invalid conflict choice")
	}
	detail := report.record(space.Name, rel, "conflict", "conflict", 0, nil)
	if detail != nil {
		detail.SpaceID = space.ID
		detail.LocalSHA = localSHA
		detail.SHA256 = remote.SHA256
		detail.ServerCopy = conflict.ServerCopy
		detail.MappedPath = strings.TrimPrefix(remote.Path, strings.Trim(space.Prefix, "/")+"/")
	}
	return "", nil
}
