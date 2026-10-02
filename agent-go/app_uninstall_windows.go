package main

// Unattended application removal. Never guess switches for an unknown installer.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	windowsPkg "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func findAppUninstallEntry(productName string) (appUninstallEntry, error) {
	var matches []appUninstallEntry
	roots := []struct {
		hive registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
		{registry.LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
		// Under SYSTEM this is SYSTEM's HKCU, not the signed-in user's hive.
		{registry.CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
	}
	for _, root := range roots {
		key, err := registry.OpenKey(root.hive, root.path, registry.ENUMERATE_SUB_KEYS)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return appUninstallEntry{}, fmt.Errorf("read uninstall registry: %w", err)
		}
		names, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err != nil {
			return appUninstallEntry{}, fmt.Errorf("enumerate uninstall registry: %w", err)
		}
		for _, name := range names {
			path := root.path + "\\" + name
			sub, err := registry.OpenKey(root.hive, path, registry.QUERY_VALUE)
			if errors.Is(err, registry.ErrNotExist) {
				continue
			}
			if err != nil {
				return appUninstallEntry{}, fmt.Errorf("read uninstall registration: %w", err)
			}
			display, _, displayErr := sub.GetStringValue("DisplayName")
			if displayErr == nil && strings.EqualFold(display, productName) {
				normal, _, _ := sub.GetStringValue("UninstallString")
				quiet, _, _ := sub.GetStringValue("QuietUninstallString")
				msi, _, _ := sub.GetIntegerValue("WindowsInstaller")
				matches = append(matches, appUninstallEntry{Hive: uintptr(root.hive), KeyPath: path, KeyName: name,
					DisplayName: display, UninstallString: strings.TrimSpace(normal),
					QuietUninstallString: strings.TrimSpace(quiet), WindowsInstaller: msi == 1})
			}
			sub.Close()
		}
	}
	return selectAppUninstallEntry(productName, matches)
}
func expandAppUninstallEnvironment(command string) (string, error) {
	source, err := windowsPkg.UTF16PtrFromString(command)
	if err != nil {
		return "", err
	}
	size, err := windowsPkg.ExpandEnvironmentStrings(source, nil, 0)
	if err != nil || size == 0 || size > 32768 {
		return "", fmt.Errorf("invalid expanded uninstall command size")
	}
	buffer := make([]uint16, size)
	written, err := windowsPkg.ExpandEnvironmentStrings(source, &buffer[0], size)
	if err != nil || written == 0 || written > size {
		return "", fmt.Errorf("could not expand uninstall environment")
	}
	return windowsPkg.UTF16ToString(buffer), nil
}

func planAppUninstall(entry appUninstallEntry) (appUninstallPlan, error) {
	command, quiet := registeredAppUninstallCommand(entry)
	command, expandErr := expandAppUninstallEnvironment(command)
	if expandErr != nil {
		return appUninstallPlan{}, fmt.Errorf("expand registered uninstall command: %w", expandErr)
	}
	fields, err := windowsPkg.DecomposeCommandLine(command)
	if err != nil || len(fields) == 0 || fields[0] == "" {
		return appUninstallPlan{}, fmt.Errorf("invalid registered uninstall command; no removal was started")
	}
	executable := fields[0]
	base := strings.ToLower(filepath.Base(executable))
	if base == "msiexec" || base == "msiexec.exe" {
		systemDir, err := windowsPkg.GetSystemDirectory()
		if err != nil {
			return appUninstallPlan{}, err
		}
		trusted := filepath.Join(systemDir, "msiexec.exe")
		if filepath.IsAbs(executable) {
			cleaned, pathErr := canonicalPath(executable)
			if pathErr != nil {
				return appUninstallPlan{}, pathErr
			}
			if !strings.EqualFold(cleaned, trusted) {
				windowsDir, dirErr := windowsPkg.GetWindowsDirectory()
				if dirErr != nil || !strings.EqualFold(cleaned, filepath.Join(windowsDir, "SysWOW64", "msiexec.exe")) {
					return appUninstallPlan{}, fmt.Errorf("untrusted Windows Installer executable; no removal was started")
				}
			}
			trusted = cleaned
		} else if strings.ContainsAny(executable, "\\/") {
			return appUninstallPlan{}, fmt.Errorf("invalid Windows Installer executable")
		}
		executable = trusted // never resolve bare msiexec through PATH
	} else {
		executable, err = resolveAllowedPath(executable, []string{"c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\"})
		if err != nil {
			return appUninstallPlan{}, fmt.Errorf("uninstall executable outside allowed locations: %w", err)
		}
		if !strings.EqualFold(filepath.Ext(executable), ".exe") {
			return appUninstallPlan{}, fmt.Errorf("registered uninstaller must be an executable")
		}
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return appUninstallPlan{}, fmt.Errorf("registered uninstall executable is missing or not a regular file")
	}
	args, mode, err := appUninstallArgs(entry, executable, fields[1:], quiet)
	if err != nil {
		return appUninstallPlan{}, err
	}
	return appUninstallPlan{Executable: executable, Args: args, Mode: mode}, nil
}
func appUninstallRegistrationPresent(entry appUninstallEntry) (bool, error) {
	key, err := registry.OpenKey(registry.Key(entry.Hive), entry.KeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	key.Close()
	return true, nil
}
func runAppUninstall(productName string) (int, string, error) {
	entry, err := findAppUninstallEntry(productName)
	if err != nil {
		return 1, "", err
	}
	plan, err := planAppUninstall(entry)
	if err != nil {
		return 1, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), jobTimeoutSec*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, plan.Executable, plan.Args...)
	out, runErr := boundedCombinedOutput(cmd)
	code := 0
	if runErr != nil {
		code = 1
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			code = exit.ExitCode()
		}
	}
	timedOut := ctx.Err() == context.DeadlineExceeded
	if timedOut || (runErr != nil && !(strings.HasPrefix(plan.Mode, "Windows Installer") && code == 3010)) {
		return appUninstallResult(plan.Mode, code, string(out), runErr, timedOut, true, nil, jobTimeoutSec)
	}
	present, verifyErr := appUninstallRegistrationPresent(entry)
	for attempt := 0; attempt < 10 && present && verifyErr == nil && ctx.Err() == nil; attempt++ {
		time.Sleep(500 * time.Millisecond)
		present, verifyErr = appUninstallRegistrationPresent(entry)
	}
	return appUninstallResult(plan.Mode, code, string(out), runErr, false, present, verifyErr, jobTimeoutSec)
}
