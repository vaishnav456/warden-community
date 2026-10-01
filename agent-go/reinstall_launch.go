package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const reinstallLaunchTimeout = 90 * time.Second
const reinstallRetryInterval = 30 * time.Second

// Retry a bounded launcher; callers use one direct launch plus the same boot task.
// Clock injection keeps delayed-launch and timeout regressions deterministic.
func waitForReinstallLaunch(probe func() (bool, error), launch func() error,
	now func() time.Time, sleep func(time.Duration), timeout time.Duration) error {
	deadline := now().Add(timeout)
	nextLaunch := now()
	var launchErr error
	for {
		started, err := probe()
		if err != nil {
			return fmt.Errorf("read verified updater startup marker: %w", err)
		}
		if started {
			return nil
		}
		current := now()
		if !current.Before(deadline) {
			if launchErr != nil {
				return fmt.Errorf("updater did not start within %s; last task launch failed: %w", timeout, launchErr)
			}
			return fmt.Errorf("updater task remained queued or failed to launch within %s", timeout)
		}
		if !current.Before(nextLaunch) {
			launchErr = launch()
			nextLaunch = current.Add(reinstallRetryInterval)
		}
		sleep(250 * time.Millisecond)
	}
}

func reinstallHelperStarted(statusPath string) (bool, error) {
	data, err := os.ReadFile(statusPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// A shell marker alone is not proof that the verified helper ran.
	return strings.Contains(string(data), "Verified reinstall helper started"), nil
}

func startDetachedReinstallHelper(path string, args []string) error {
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func acquireReinstallLock(handoffDir string) (windows.Handle, error) {
	path, err := windows.UTF16PtrFromString(filepath.Join(handoffDir, "helper.lock"))
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
}

func reinstallHandoffAllowed(handoffDir string) bool {
	authorization, err := os.ReadFile(filepath.Join(handoffDir, "authorized"))
	if err != nil || string(authorization) != "prepared" {
		return false
	}
	_, err = os.Stat(filepath.Join(handoffDir, "cancelled"))
	// Unreadable cancellation state fails closed.
	return os.IsNotExist(err)
}

func cancelReinstallHandoff(handoffDir string) error {
	// Removing authorization works even when a full disk prevents writing
	// the explanatory cancellation marker. Either fence prevents a late start.
	removalErr := os.Remove(filepath.Join(handoffDir, "authorized"))
	if os.IsNotExist(removalErr) {
		removalErr = nil
	}
	markerErr := os.WriteFile(filepath.Join(handoffDir, "cancelled"), []byte("launch failed"), 0600)
	if removalErr != nil && markerErr != nil {
		return fmt.Errorf("cannot revoke handoff: %v; cancellation marker: %w", removalErr, markerErr)
	}
	return nil
}

// A boot-triggered helper may resume after power loss during replacement.
// Never overwrite the original rollback copy with a partly replaced binary.
func preserveReinstallBackup(installed, backup, originalSHA256 string) error {
	if _, err := os.Stat(backup); err == nil {
		hash, err := fileSHA256(backup)
		if err != nil || hash != originalSHA256 {
			return fmt.Errorf("original rollback copy failed integrity verification")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	hash, err := fileSHA256(installed)
	if err != nil || hash != originalSHA256 {
		return fmt.Errorf("installed agent changed before rollback backup")
	}
	if err := copyFile(installed, backup); err != nil {
		return err
	}
	hash, err = fileSHA256(backup)
	if err != nil || hash != originalSHA256 {
		return fmt.Errorf("rollback copy failed integrity verification")
	}
	return nil
}
