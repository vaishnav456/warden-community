package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type bitLockerVolumeStatus struct {
	MountPoint           string   `json:"mount_point"`
	ProtectorIDs         []string `json:"protector_ids"`
	VolumeStatus         string   `json:"volume_status"`
	ProtectionStatus     string   `json:"protection_status"`
	EncryptionPercentage float64  `json:"encryption_percentage"`
}
type bitLockerStatusSnapshot struct {
	CollectedAt string                  `json:"collected_at"`
	Volumes     []bitLockerVolumeStatus `json:"volumes"`
}

var bitLockerTelemetry struct {
	sync.Mutex
	pending *bitLockerStatusSnapshot
}

// Never serialize the BitLockerVolume object or recovery password. This query
// reads status and protector IDs only; it does not change protectors/encryption.
const collectBitLockerStatusScript = `$ErrorActionPreference='Stop'
$volumes=@(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
 [pscustomobject]@{
  mount_point=[string]$_.MountPoint
  protector_ids=@($_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | ForEach-Object {[string]$_.KeyProtectorId})
  volume_status=[string]$_.VolumeStatus
  protection_status=[string]$_.ProtectionStatus
  encryption_percentage=[double]$_.EncryptionPercentage
 }
})
[pscustomobject]@{volumes=$volumes} | ConvertTo-Json -Depth 4 -Compress`

func readBitLockerStatus(run func(string, []string, time.Duration) ([]byte, error)) (*bitLockerStatusSnapshot, error) {
	raw, err := run(collectBitLockerStatusScript, nil, 20*time.Second)
	if err != nil {
		return nil, err
	}
	if len(raw) > 65536 {
		return nil, fmt.Errorf("BitLocker metadata exceeds limit")
	}
	var snapshot bitLockerStatusSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	if len(snapshot.Volumes) > 32 {
		return nil, fmt.Errorf("too many BitLocker volumes")
	}
	snapshot.CollectedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return &snapshot, nil
}

func runBitLockerStatusCollector(stopCh <-chan struct{}) {
	collect := func() {
		snapshot, err := readBitLockerStatus(runPowerShellSecret)
		if err != nil {
			// Keep pending successful telemetry for retry, but never manufacture
			// an Off/0% state when BitLocker is unavailable or a query fails.
			return
		}
		bitLockerTelemetry.Lock()
		bitLockerTelemetry.pending = snapshot
		bitLockerTelemetry.Unlock()
	}
	collect()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			collect()
		case <-stopCh:
			return
		}
	}
}

func pendingBitLockerStatus() *bitLockerStatusSnapshot {
	bitLockerTelemetry.Lock()
	defer bitLockerTelemetry.Unlock()
	snapshot := bitLockerTelemetry.pending
	if snapshot == nil {
		return nil
	}
	captured, err := time.Parse(time.RFC3339Nano, snapshot.CollectedAt)
	if err != nil || time.Since(captured) > 2*time.Minute {
		return nil
	}
	return snapshot
}

func acknowledgeBitLockerStatus(sent *bitLockerStatusSnapshot) {
	if sent == nil {
		return
	}
	bitLockerTelemetry.Lock()
	defer bitLockerTelemetry.Unlock()
	// Do not discard a newer collection that completed during the HTTP request.
	if bitLockerTelemetry.pending == sent {
		bitLockerTelemetry.pending = nil
	}
}
