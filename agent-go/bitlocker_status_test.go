package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBitLockerTelemetryContainsNoRecoveryPassword(t *testing.T) {
	snapshot, err := readBitLockerStatus(func(script string, env []string, timeout time.Duration) ([]byte, error) {
		if strings.Contains(script, ".RecoveryPassword") || len(env) != 0 {
			t.Fatal("status query reads a recovery password")
		}
		return []byte(`{"volumes":[{"mount_point":"C:","protector_ids":["{AE0802F2-7FC8-4049-A62D-7C4FD16627F8}"],"volume_status":"FullyEncrypted","protection_status":"On","encryption_percentage":100,"recovery_password":"SECRET-MUST-NOT-LEAVE"}]}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "recovery_password") {
		t.Fatal("secret leaked into telemetry")
	}
	if len(snapshot.Volumes) != 1 || snapshot.Volumes[0].EncryptionPercentage != 100 || snapshot.CollectedAt == "" {
		t.Fatal("status missing")
	}
}

func TestBitLockerTelemetryQueryFailureDoesNotCreateOffStatus(t *testing.T) {
	snapshot, err := readBitLockerStatus(func(string, []string, time.Duration) ([]byte, error) { return nil, errors.New("unavailable") })
	if err == nil || snapshot != nil {
		t.Fatal("failed query manufactured a status")
	}
	snapshot, err = readBitLockerStatus(func(string, []string, time.Duration) ([]byte, error) { return []byte("invalid"), nil })
	if err == nil || snapshot != nil {
		t.Fatal("invalid query manufactured a status")
	}
}

func TestBitLockerTelemetryAcknowledgementPreservesNewerSnapshot(t *testing.T) {
	first := &bitLockerStatusSnapshot{CollectedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	newer := &bitLockerStatusSnapshot{CollectedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	bitLockerTelemetry.Lock()
	original := bitLockerTelemetry.pending
	bitLockerTelemetry.pending = newer
	bitLockerTelemetry.Unlock()
	defer func() { bitLockerTelemetry.Lock(); bitLockerTelemetry.pending = original; bitLockerTelemetry.Unlock() }()
	acknowledgeBitLockerStatus(first)
	if pendingBitLockerStatus() != newer {
		t.Fatal("discarded newer telemetry")
	}
	acknowledgeBitLockerStatus(newer)
	if pendingBitLockerStatus() != nil {
		t.Fatal("acknowledged telemetry not cleared")
	}
}

func TestBitLockerTelemetryStaleSnapshotIsNotReportedAsFresh(t *testing.T) {
	bitLockerTelemetry.Lock()
	original := bitLockerTelemetry.pending
	bitLockerTelemetry.pending = &bitLockerStatusSnapshot{CollectedAt: time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339Nano)}
	bitLockerTelemetry.Unlock()
	defer func() { bitLockerTelemetry.Lock(); bitLockerTelemetry.pending = original; bitLockerTelemetry.Unlock() }()
	if pendingBitLockerStatus() != nil {
		t.Fatal("stale snapshot reported")
	}
}
