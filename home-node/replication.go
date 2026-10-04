package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type peer struct {
	SpaceID        string   `json:"space_id"`
	TargetNodeID   string   `json:"target_node_id"`
	ConnectionMode string   `json:"connection_mode"`
	P2PURL         string   `json:"p2p_url"`
	STUNURLs       []string `json:"stun_urls"`
	LocalURL       string   `json:"local_url"`
	PublicURL      string   `json:"public_url"`
	TLSFingerprint string   `json:"tls_fingerprint"`
	CACertificate  string   `json:"ca_certificate_pem"`
	Prefix         string   `json:"prefix"`
	Grant          string   `json:"grant"`
	MaxFileBytes   int64    `json:"max_file_bytes"`
	QuotaBytes     int64    `json:"quota_bytes"`
	HistoryDays    int      `json:"history_days"`
}

func replicationStatePath() string {
	return filepath.Join(cfg.Root, ".warden-replication-state.json")
}

func loadReplicationState() error {
	state := map[string]int64{}
	raw, err := os.ReadFile(replicationStatePath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &state); err != nil {
			return fmt.Errorf("invalid replication state: %w", err)
		}
	}
	now := time.Now().Unix()
	for spaceID, syncedAt := range state {
		if strings.TrimSpace(spaceID) == "" || syncedAt <= 0 || syncedAt > now+300 {
			delete(state, spaceID)
		}
	}
	replicationMu.Lock()
	replicationOK = state
	replicationMu.Unlock()
	return nil
}

func recordReplicationSuccess(spaceID string) (bool, error) {
	replicationMu.Lock()
	defer replicationMu.Unlock()
	next := make(map[string]int64, len(replicationOK)+1)
	for id, syncedAt := range replicationOK {
		next[id] = syncedAt
	}
	first := next[spaceID] == 0
	next[spaceID] = time.Now().Unix()
	raw, err := json.Marshal(next)
	if err != nil {
		return false, err
	}
	if err := atomicWrite(replicationStatePath(), append(raw, '\n'), 0600); err != nil {
		return false, err
	}
	replicationOK = next
	return first, nil
}

func replicateFrom(p peer) {
	replicationKey := p.SpaceID + ":" + p.TargetNodeID
	if _, loaded := replicationActive.LoadOrStore(replicationKey, true); loaded {
		return
	}
	defer replicationActive.Delete(replicationKey)
	base := p.P2PURL
	if p.ConnectionMode != "p2p" {
		base = p.LocalURL
		if base == "" {
			base = p.PublicURL
		}
	}
	if base == "" {
		return
	}
	client, err := tlsClientForPeer(p)
	if err != nil {
		return
	}
	listURL := strings.TrimRight(base, "/") + "/v1/list?include_directories=1&include_deletions=1&path=" + url.QueryEscape(p.Prefix)
	req, _ := http.NewRequest(http.MethodGet, listURL, nil)
	req.Header.Set("Authorization", "Bearer "+p.Grant)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var entries []fileEntry
	if json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&entries) != nil {
		return
	}
	remotePaths := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		remotePaths[entry.Path] = struct{}{}
	}
	allOK := true
	for _, entry := range entries {
		if entry.Path != p.Prefix && !strings.HasPrefix(entry.Path, strings.TrimRight(p.Prefix, "/")+"/") {
			allOK = false
			continue
		}
		if entry.Deleted {
			storageMu.Lock()
			release, err := acquireSpaceLock(p.Prefix)
			if err != nil {
				allOK = false
			} else {
				if err := archiveHomeVersion(entry.Path, p.HistoryDays, true); err != nil {
					allOK = false
				} else if err := writeHomeDeletion(entry.Path, homeDeletion{SHA256: entry.SHA256, Size: entry.Size, DeletedAt: entry.ModTime}); err != nil {
					allOK = false
				}
				release()
			}
			storageMu.Unlock()
			continue
		}
		if entry.IsDir {
			if entry.Path != p.Prefix && !strings.HasPrefix(entry.Path, strings.TrimRight(p.Prefix, "/")+"/") {
				allOK = false
				continue
			}
			storageMu.Lock()
			release, err := acquireSpaceLock(p.Prefix)
			if err != nil {
				allOK = false
			} else {
				if err := createStoredDirectory(entry.Path); err != nil {
					allOK = false
				}
				release()
			}
			storageMu.Unlock()
			continue
		}
		_, metaPath, err := pathsFor(entry.Path)
		if err != nil {
			continue
		}
		deletion, deletionErr := readHomeDeletion(entry.Path)
		if deletionErr != nil {
			allOK = false
			continue
		}
		if local := loadMeta(metaPath); deletion == nil && local.Exists && local.Valid && local.Size == entry.Size && entry.SHA256 != "" && local.SHA256 == entry.SHA256 {
			continue
		}
		u := strings.TrimRight(base, "/") + "/v1/file?path=" + url.QueryEscape(entry.Path)
		get, _ := http.NewRequest(http.MethodGet, u, nil)
		get.Header.Set("Authorization", "Bearer "+p.Grant)
		fileResp, err := client.Do(get)
		if err != nil {
			allOK = false
			continue
		}
		if fileResp.StatusCode == 200 {
			storageMu.Lock()
			release, lockErr := acquireSpaceLock(p.Prefix)
			if lockErr == nil {
				// The authoritative primary now lists an active file at this path.
				// Replace a replica's old tombstone only after verified download.
				readdVersion := ""
				if deletion, err := readHomeDeletion(entry.Path); err == nil && deletion != nil {
					readdVersion = homeDeletionVersion(deletion)
				}
				_, writeErr := storeAuthorizedFileVerified(entry.Path, fileResp.Body, entry.ModTime, grant{
					Prefix: p.Prefix, MaxFileBytes: p.MaxFileBytes, QuotaBytes: p.QuotaBytes, HistoryDays: p.HistoryDays,
				}, entry.SHA256, readdVersion)
				if writeErr != nil {
					allOK = false
				}
				release()
			} else {
				allOK = false
			}
			storageMu.Unlock()
		} else {
			allOK = false
		}
		fileResp.Body.Close()
	}
	// A replica is an exact mirror, including deletions. Apply removals only
	// after a complete, successful remote listing and download pass so a
	// transient or truncated response can never erase backup data.
	if allOK {
		storageMu.Lock()
		release, lockErr := acquireSpaceLock(p.Prefix)
		if lockErr != nil {
			allOK = false
		} else {
			localEntries, listErr := listStoredFiles(p.Prefix)
			if listErr != nil {
				allOK = false
			} else {
				for _, local := range localEntries {
					if _, exists := remotePaths[local.Path]; exists {
						continue
					}
					dataPath, metaPath, pathErr := pathsFor(local.Path)
					if pathErr != nil {
						allOK = false
						continue
					}
					if err := os.Remove(dataPath); err != nil && !os.IsNotExist(err) {
						allOK = false
					}
					if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
						allOK = false
					}
				}
			}
			release()
		}
		storageMu.Unlock()
	}
	if allOK {
		firstSuccessfulSync, stateErr := recordReplicationSuccess(p.SpaceID)
		if stateErr != nil {
			log.Printf("Persist replication readiness for %s: %v", p.SpaceID, stateErr)
		} else if firstSuccessfulSync {
			select {
			case replicationReady <- struct{}{}:
			default:
			}
		}
	}
}
