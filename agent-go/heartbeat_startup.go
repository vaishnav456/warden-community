package main

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// A stable per-endpoint phase avoids synchronized restarts/reconnections.
// Only startup is delayed; the regular 30-second heartbeat interval is unchanged.
func heartbeatStartupDelay(endpointID string) time.Duration {
	if endpointID == "" {
		return 0
	}
	digest := sha256.Sum256([]byte(endpointID))
	return time.Duration(binary.LittleEndian.Uint64(digest[:8]) % uint64(pollIntervalSec*time.Second))
}

func waitForHeartbeatStartup(stopCh <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-stopCh:
		return false
	case <-timer.C:
		select {
		case <-stopCh:
			return false
		default:
			return true
		}
	}
}
