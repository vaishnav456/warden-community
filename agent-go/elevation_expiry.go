package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var elevationMu sync.Mutex

func loadElevations() map[string]int64 {
	entries := make(map[string]int64)
	data, err := os.ReadFile(elevationsPath)
	if err == nil {
		_ = json.Unmarshal(data, &entries)
	}
	return entries
}

func saveElevations(entries map[string]int64) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	tmp := elevationsPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, elevationsPath)
}

func recordElevationExpiry(username string, durationMinutes int64) error {
	if durationMinutes < 1 || durationMinutes > 1440 {
		return fmt.Errorf("duration_minutes must be between 1 and 1440")
	}
	elevationMu.Lock()
	defer elevationMu.Unlock()
	entries := loadElevations()
	entries[strings.ToLower(username)] = time.Now().Unix() + durationMinutes*60
	return saveElevations(entries)
}

func removeElevationExpiry(username string) error {
	elevationMu.Lock()
	defer elevationMu.Unlock()
	entries := loadElevations()
	delete(entries, strings.ToLower(username))
	return saveElevations(entries)
}

func revokeExpiredElevations() {
	elevationMu.Lock()
	defer elevationMu.Unlock()
	entries := loadElevations()
	now := time.Now().Unix()
	changed := false
	for username, expiresAt := range entries {
		if expiresAt > now {
			continue
		}
		out, err := exec.Command(
			"net", "localgroup", "Administrators", username, "/delete",
		).CombinedOutput()
		if err != nil {
			logWarn(
				"Could not revoke expired elevation for %s: %v: %s",
				username, err, string(out),
			)
			continue
		}
		delete(entries, username)
		changed = true
		logInfo("Revoked expired temporary elevation for %s", username)
	}
	if changed {
		if err := saveElevations(entries); err != nil {
			logWarn("Could not persist elevation expiry cleanup: %v", err)
		}
	}
}
