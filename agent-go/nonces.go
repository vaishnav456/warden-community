package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	nonceTTLSec = 300
	jobTTLSec   = 90 * 24 * 60 * 60
)

type replayEntry struct {
	CreatedAt int64 `json:"created_at"`
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

type completedJob struct {
	Status      string `json:"status"`
	ExitCode    int    `json:"exit_code"`
	LogOutput   string `json:"log_output"`
	ErrorMsg    string `json:"error_msg"`
	CompletedAt int64  `json:"completed_at"`
}

type replayStore struct {
	Nonces         map[string]replayEntry  `json:"nonces"`
	Jobs           map[string]completedJob `json:"jobs"`
	PendingReports map[string]completedJob `json:"pending_reports,omitempty"`
}

var (
	replayMu sync.Mutex
	replays  = replayStore{
		Nonces:         make(map[string]replayEntry),
		Jobs:           make(map[string]completedJob),
		PendingReports: make(map[string]completedJob),
	}
)

func initReplayStore() error {
	replayMu.Lock()
	defer replayMu.Unlock()
	data, err := os.ReadFile(noncesPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read replay store: %w", err)
	}
	if err := json.Unmarshal(data, &replays); err != nil {
		return fmt.Errorf("decode replay store: %w", err)
	}
	if replays.Nonces == nil {
		replays.Nonces = make(map[string]replayEntry)
	}
	if replays.Jobs == nil {
		replays.Jobs = make(map[string]completedJob)
	}
	if replays.PendingReports == nil {
		replays.PendingReports = make(map[string]completedJob)
	}
	return nil
}

func saveReplayStoreLocked() error {
	data, err := json.Marshal(replays)
	if err != nil {
		return err
	}
	tmp := noncesPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, noncesPath)
}

func checkAndConsumeNonce(nonce string, envelopeExpiresAt int64) error {
	if nonce == "" {
		return fmt.Errorf("empty nonce")
	}
	replayMu.Lock()
	defer replayMu.Unlock()
	if _, exists := replays.Nonces[nonce]; exists {
		return fmt.Errorf("replay attack detected — nonce already used: %s", nonce)
	}
	replays.Nonces[nonce] = replayEntry{
		CreatedAt: time.Now().Unix(), ExpiresAt: envelopeExpiresAt,
	}
	if err := saveReplayStoreLocked(); err != nil {
		delete(replays.Nonces, nonce)
		return fmt.Errorf("persist consumed nonce: %w", err)
	}
	return nil
}

func getCompletedJob(jobID string) (completedJob, bool) {
	replayMu.Lock()
	defer replayMu.Unlock()
	result, ok := replays.Jobs[jobID]
	return result, ok
}

func recordCompletedJob(jobID string, result completedJob) error {
	if jobID == "" {
		return fmt.Errorf("empty job_id")
	}
	replayMu.Lock()
	defer replayMu.Unlock()
	result.CompletedAt = time.Now().Unix()
	replays.Jobs[jobID] = result
	replays.PendingReports[jobID] = result
	return saveReplayStoreLocked()
}

func pendingJobReports() map[string]completedJob {
	replayMu.Lock()
	defer replayMu.Unlock()
	copyOfReports := make(map[string]completedJob, len(replays.PendingReports))
	for jobID, result := range replays.PendingReports {
		copyOfReports[jobID] = result
	}
	return copyOfReports
}

func acknowledgeJobReport(jobID string) error {
	replayMu.Lock()
	defer replayMu.Unlock()
	if _, exists := replays.PendingReports[jobID]; !exists {
		return nil
	}
	delete(replays.PendingReports, jobID)
	if err := saveReplayStoreLocked(); err != nil {
		// Keep the report pending if acknowledgement persistence failed.
		if result, ok := replays.Jobs[jobID]; ok {
			replays.PendingReports[jobID] = result
		}
		return err
	}
	return nil
}

func cleanupExpiredNonces() {
	now := time.Now().Unix()
	replayMu.Lock()
	defer replayMu.Unlock()
	changed := false
	for k, v := range replays.Nonces {
		keepUntil := v.ExpiresAt + int64(maxCommandClockSkew/time.Second)
		if v.ExpiresAt == 0 {
			// Backward-compatible cleanup for entries written by older agents.
			keepUntil = v.CreatedAt + nonceTTLSec
		}
		if keepUntil < now {
			delete(replays.Nonces, k)
			changed = true
		}
	}
	for k, v := range replays.Jobs {
		if _, pending := replays.PendingReports[k]; !pending && v.CompletedAt < now-jobTTLSec {
			delete(replays.Jobs, k)
			changed = true
		}
	}
	if changed {
		if err := saveReplayStoreLocked(); err != nil {
			logWarn("Could not persist replay-store cleanup: %v", err)
		}
	}
}
