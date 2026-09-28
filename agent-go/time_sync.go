package main

import (
	"strings"
	"sync"
	"time"
)

const (
	automaticClockCorrectionThreshold = 90 * time.Second
)

var (
	timeReconcileMu       sync.Mutex
	lastAppliedTimezone   string
	lastClockCorrectionAt time.Time
)

func absoluteDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func clockCorrectionNeeded(serverNow, localNow time.Time) bool {
	drift := absoluteDuration(serverNow.Sub(localNow))
	// The timestamp arrived over Warden's certificate-pinned, mutually
	// authenticated channel. Once that channel succeeds, it is safer to repair
	// even a badly skewed cloned/hibernated VM than to leave certificate renewal
	// and signed-job expiry permanently broken.
	return drift >= automaticClockCorrectionThreshold
}

func validTimeZoneName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 32 || character == 127 {
			return false
		}
	}
	return true
}

func reconcileEndpointClock(serverTimeRaw, branchTimezone string) {
	serverNow, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(serverTimeRaw))
	if err != nil {
		logWarn("Ignoring invalid Warden server time: %v", err)
		return
	}
	timeReconcileMu.Lock()
	defer timeReconcileMu.Unlock()

	localNow := time.Now()
	if clockCorrectionNeeded(serverNow, localNow) && time.Since(lastClockCorrectionAt) >= 5*time.Minute {
		drift := serverNow.Sub(localNow)
		if err := setSystemTimeUTC(serverNow.UTC()); err != nil {
			logWarn("Automatic clock correction failed: %v", err)
		} else {
			lastClockCorrectionAt = time.Now()
			logInfo("Corrected endpoint clock by %s from Warden's pinned HTTPS response.", drift.Round(time.Second))
		}
	}

	branchTimezone = strings.TrimSpace(branchTimezone)
	if !validTimeZoneName(branchTimezone) || branchTimezone == lastAppliedTimezone {
		return
	}
	changed, err := applySystemTimeZone(branchTimezone)
	if err != nil {
		logWarn("Could not apply branch time zone %q: %v", branchTimezone, err)
		return
	}
	lastAppliedTimezone = branchTimezone
	if changed {
		logInfo("Applied branch time zone %q.", branchTimezone)
	}
}
