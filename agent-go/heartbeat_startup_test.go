package main

import (
	"fmt"
	"testing"
	"time"
)

func TestHeartbeatStartupPhaseIsStable(t *testing.T) {
	if heartbeatStartupDelay("endpoint-a") != heartbeatStartupDelay("endpoint-a") {
		t.Fatal("unstable phase")
	}
	if heartbeatStartupDelay("endpoint-a") == heartbeatStartupDelay("endpoint-b") {
		t.Fatal("identical phases")
	}
}
func TestHeartbeatStartupPhaseIsBoundedAndDistributed(t *testing.T) {
	var buckets [10]int
	for i := 0; i < 1000; i++ {
		delay := heartbeatStartupDelay(fmt.Sprintf("synthetic-%d", i))
		if delay < 0 || delay >= pollIntervalSec*time.Second {
			t.Fatal("outside poll window")
		}
		buckets[int(delay/(3*time.Second))]++
	}
	for _, count := range buckets {
		if count < 50 || count > 150 {
			t.Fatalf("unbalanced phases: %v", buckets)
		}
	}
}
func TestHeartbeatStartupEmptyIdentityHasNoDelay(t *testing.T) {
	if heartbeatStartupDelay("") != 0 {
		t.Fatal("empty identity must not delay")
	}
}
func TestHeartbeatStartupStopCancelsDelay(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	if waitForHeartbeatStartup(stop, time.Hour) {
		t.Fatal("ignored stop")
	}
}
func TestHeartbeatStartupZeroDelayStillHonorsStop(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	if waitForHeartbeatStartup(stop, 0) {
		t.Fatal("ignored stop")
	}
}
func TestHeartbeatStartupNormalDelayCompletes(t *testing.T) {
	if !waitForHeartbeatStartup(make(chan struct{}), time.Millisecond) {
		t.Fatal("unexpected stop")
	}
}
