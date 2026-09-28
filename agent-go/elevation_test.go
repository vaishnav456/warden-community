package main

import (
	"os"
	"strings"
	"testing"
)

func resetSessionChangeState() {
	sessionLockMu.Lock()
	sessionLockKnown = false
	sessionLocked = false
	sessionLockID = 0
	sessionLockMu.Unlock()
}

func TestSessionChangeKeepsWinlogonStableAcrossLogoff(t *testing.T) {
	resetSessionChangeState()
	t.Cleanup(resetSessionChangeState)

	applySessionChange(4, wtsSessionLock)
	applySessionChange(4, wtsSessionLogoff)
	if locked, known := knownSessionLockState(4); !known || !locked {
		t.Fatalf("logoff must keep session on Winlogon: locked=%v known=%v", locked, known)
	}
}

func TestSessionChangeReturnsToDefaultOnLogonOrUnlock(t *testing.T) {
	resetSessionChangeState()
	t.Cleanup(resetSessionChangeState)

	applySessionChange(7, wtsSessionLogoff)
	applySessionChange(7, wtsSessionLogon)
	if locked, known := knownSessionLockState(7); !known || locked {
		t.Fatalf("logon must select Default: locked=%v known=%v", locked, known)
	}

	applySessionChange(7, wtsSessionLock)
	applySessionChange(7, wtsSessionUnlock)
	if locked, known := knownSessionLockState(7); !known || locked {
		t.Fatalf("unlock must select Default: locked=%v known=%v", locked, known)
	}
}

func TestSessionChangeStateIsScopedToConsoleSession(t *testing.T) {
	resetSessionChangeState()
	t.Cleanup(resetSessionChangeState)

	applySessionChange(9, wtsSessionLogoff)
	if _, known := knownSessionLockState(10); known {
		t.Fatal("state from a different console session must not be reused")
	}
}

func TestDesktopNamesDifferIsCaseInsensitive(t *testing.T) {
	if desktopNamesDiffer("Default", "default") {
		t.Fatal("same desktop name with different case must not trigger a helper switch")
	}
	if !desktopNamesDiffer("Default", "Winlogon") {
		t.Fatal("secure desktop transition must trigger a helper switch")
	}
	if desktopNamesDiffer("", "Winlogon") {
		t.Fatal("an unavailable desktop name is not enough to infer a switch")
	}
}

func TestRemoteRelayUsesInputDesktopAsSwitchAuthority(t *testing.T) {
	source, err := os.ReadFile("remote.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, "desktopPoll :=") || strings.Contains(text, "Remote console desktop changed") {
		t.Fatal("relay must not override OpenInputDesktop decisions with stale session state")
	}
	if !strings.Contains(text, "Remote relay input desktop changed") {
		t.Fatal("relay no longer handles helper-reported input desktop changes")
	}
}
