package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"
)

type heartbeatResponse struct {
	OK               bool           `json:"ok"`
	ServerPublicKey  string         `json:"server_public_key"`
	ReplicationPeers []peer         `json:"replication_peers"`
	Update           *managedUpdate `json:"update"`
}

func heartbeatLoop(stop <-chan struct{}) {
	client := homeControlClient()
	for {
		if err := ensureNodeCertificate(configPathInUse, 48*time.Hour); err != nil {
			log.Printf("Warden Home certificate renewal deferred: %v", err)
		}
		capacity, used := diskUsage()
		replicationMu.Lock()
		replicationState := make(map[string]int64, len(replicationOK))
		for spaceID, syncedAt := range replicationOK {
			replicationState[spaceID] = syncedAt
		}
		replicationMu.Unlock()
		body, _ := json.Marshal(map[string]interface{}{"capacity_bytes": capacity, "used_bytes": used, "capabilities": map[string]interface{}{"os": runtime.GOOS, "arch": runtime.GOARCH, "version": homeNodeVersion, "managed_updates": true, "encrypted_at_rest": true, "encrypted_history": true, "encryption_key_id": encryptionKeyID, "replication": cfg.Replication, "p2p": true, "p2p_transport": "webrtc-direct", "replication_sync": replicationState, "storage_cluster_id": cfg.StorageClusterID, "independent_backup": backupStatus(), "package_cache": cfg.PackageCacheMaxBytes > 0}})
		req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.WardenURL, "/")+"/api/home-node/heartbeat", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Warden-Home-Key", cfg.NodeKey)
		if resp, err := client.Do(req); err == nil {
			var result heartbeatResponse
			_ = json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&result)
			resp.Body.Close()
			if cfg.Replication {
				for _, p := range result.ReplicationPeers {
					go replicateFrom(p)
				}
			}
			considerManagedUpdate(result.Update)
		}
		select {
		case <-stop:
			return
		case <-replicationReady:
		case <-time.After(5 * time.Minute):
		}
	}
}
