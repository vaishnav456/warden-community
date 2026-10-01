package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func simulateLaunch(t *testing.T, delay, timeout time.Duration, launchError error) (int, error) {
	t.Helper()
	start := time.Unix(0, 0)
	clock := start
	launches := 0
	err := waitForReinstallLaunch(func() (bool, error) { return clock.Sub(start) >= delay, nil },
		func() error { launches++; return launchError },
		func() time.Time { return clock }, func(d time.Duration) { clock = clock.Add(d) }, timeout)
	return launches, err
}

func TestReinstallDelayedLaunchBeyondOldTimeout(t *testing.T) {
	launches, err := simulateLaunch(t, 45*time.Second, reinstallLaunchTimeout, nil)
	if err != nil || launches != 2 {
		t.Fatalf("launches=%d err=%v", launches, err)
	}
}
func TestReinstallLaunchRetriesAreBounded(t *testing.T) {
	launches, err := simulateLaunch(t, time.Hour, reinstallLaunchTimeout, nil)
	if err == nil || launches != 3 {
		t.Fatalf("launches=%d err=%v", launches, err)
	}
}
func TestReinstallImmediateMarkerDoesNotRelaunch(t *testing.T) {
	launches, err := simulateLaunch(t, 0, reinstallLaunchTimeout, nil)
	if err != nil || launches != 0 {
		t.Fatalf("launches=%d err=%v", launches, err)
	}
}
func TestReinstallTransientSchedulerFailureCanRecover(t *testing.T) {
	_, err := simulateLaunch(t, 35*time.Second, reinstallLaunchTimeout, errors.New("scheduler busy"))
	if err != nil {
		t.Fatal(err)
	}
}
func TestReinstallPermanentSchedulerFailureIsReported(t *testing.T) {
	failure := errors.New("scheduler unavailable")
	_, err := simulateLaunch(t, time.Hour, reinstallLaunchTimeout, failure)
	if !errors.Is(err, failure) {
		t.Fatalf("lost scheduler diagnostic: %v", err)
	}
}
func TestReinstallMarkerAtDeadlineIsAccepted(t *testing.T) {
	_, err := simulateLaunch(t, reinstallLaunchTimeout, reinstallLaunchTimeout, nil)
	if err != nil {
		t.Fatal(err)
	}
}
func TestReinstallProbeFailureStopsWithoutLaunching(t *testing.T) {
	failure := errors.New("marker access denied")
	err := waitForReinstallLaunch(func() (bool, error) { return false, failure },
		func() error { t.Fatal("must not launch"); return nil }, time.Now, time.Sleep, reinstallLaunchTimeout)
	if !errors.Is(err, failure) {
		t.Fatalf("err=%v", err)
	}
}
func TestReinstallShellMarkerIsNotVerifiedStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	started, err := reinstallHelperStarted(path)
	if err != nil || started {
		t.Fatalf("missing marker: %v %v", started, err)
	}
	if err := os.WriteFile(path, []byte("Reinstall runner started"), 0600); err != nil {
		t.Fatal(err)
	}
	started, err = reinstallHelperStarted(path)
	if err != nil || started {
		t.Fatalf("shell marker: %v %v", started, err)
	}
	if err := os.WriteFile(path, []byte("Verified reinstall helper started"), 0600); err != nil {
		t.Fatal(err)
	}
	started, err = reinstallHelperStarted(path)
	if err != nil || !started {
		t.Fatalf("helper marker: %v %v", started, err)
	}
}
func TestReinstallCancellationPreventsLateHelper(t *testing.T) {
	dir := t.TempDir()
	if reinstallHandoffAllowed(dir) {
		t.Fatal("missing authorization must fail closed")
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized"), []byte("prepared"), 0600); err != nil {
		t.Fatal(err)
	}
	if !reinstallHandoffAllowed(dir) {
		t.Fatal("unexpected cancellation")
	}
	if err := os.WriteFile(filepath.Join(dir, "cancelled"), []byte("timed out"), 0600); err != nil {
		t.Fatal(err)
	}
	if reinstallHandoffAllowed(dir) {
		t.Fatal("cancelled helper may not alter services")
	}
}

func TestReinstallRevocationDoesNotNeedNewDiskSpace(t *testing.T) {
	dir := t.TempDir()
	authorization := filepath.Join(dir, "authorized")
	if err := os.WriteFile(authorization, []byte("prepared"), 0600); err != nil {
		t.Fatal(err)
	}
	// A directory at the marker path forces its write to fail, simulating an
	// unavailable marker without relying on the real machine running out of disk.
	if err := os.Mkdir(filepath.Join(dir, "cancelled"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := cancelReinstallHandoff(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(authorization); !os.IsNotExist(err) {
		t.Fatal("authorization was not removed")
	}
	if reinstallHandoffAllowed(dir) {
		t.Fatal("revoked helper must not run")
	}
}

func TestReinstallResumePreservesOriginalBackup(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "installed")
	backup := filepath.Join(dir, "backup")
	if err := os.WriteFile(installed, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := preserveReinstallBackup(installed, backup, hash); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, []byte("interrupted replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := preserveReinstallBackup(installed, backup, hash); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(backup)
	if err != nil || string(contents) != "original" {
		t.Fatalf("lost original: %q %v", contents, err)
	}
}
func TestReinstallCorruptBackupFailsClosed(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "installed")
	backup := filepath.Join(dir, "backup")
	if err := os.WriteFile(installed, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("damaged backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if preserveReinstallBackup(installed, backup, hash) == nil {
		t.Fatal("corrupt backup accepted")
	}
	contents, _ := os.ReadFile(backup)
	if string(contents) != "damaged backup" {
		t.Fatal("must not silently overwrite evidence")
	}
}
func TestReinstallChangedInstalledFileCannotBecomeBackup(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "installed")
	backup := filepath.Join(dir, "backup")
	if err := os.WriteFile(installed, []byte("not the verified running agent"), 0600); err != nil {
		t.Fatal(err)
	}
	if preserveReinstallBackup(installed, backup, "wrong-hash") == nil {
		t.Fatal("changed installed file accepted")
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("unexpected backup created")
	}
}
