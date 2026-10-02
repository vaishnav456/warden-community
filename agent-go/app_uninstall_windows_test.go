package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	windowsPkg "golang.org/x/sys/windows"
)

func TestAppMSIPlannerUsesTrustedSystemBinary(t *testing.T) {
	plan, err := planAppUninstall(appUninstallEntry{UninstallString: "msiexec.exe /I" + appTestGUID})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := windowsPkg.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(plan.Executable, filepath.Join(dir, "msiexec.exe")) || plan.Args[0] != "/x" {
		t.Fatal(plan)
	}
}
func TestAppPlannerPrefersQuietStringOverInteractive(t *testing.T) {
	plan, err := planAppUninstall(appUninstallEntry{UninstallString: "bad.exe", QuietUninstallString: "msiexec /x " + appTestGUID})
	if err != nil || !strings.HasPrefix(plan.Mode, "Windows Installer") {
		t.Fatal(plan, err)
	}
}
func TestAppPlannerRejectsUntrustedMSIExecutable(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "msiexec.exe")
	// This file is only a path fixture. It is never executed.
	if err := os.WriteFile(exe, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := planAppUninstall(appUninstallEntry{UninstallString: "\"" + exe + "\" /x " + appTestGUID}); err == nil {
		t.Fatal("untrusted msiexec accepted")
	}
}
func TestAppPlannerRejectsUninstallerOutsideProtectedRoots(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "unins000.exe")
	if err := os.WriteFile(exe, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := planAppUninstall(appUninstallEntry{KeyName: "app_is1", UninstallString: "\"" + exe + "\""}); err == nil {
		t.Fatal("unprotected executable accepted")
	}
}
func TestAppPlannerRejectsEmptyCommand(t *testing.T) {
	if _, err := planAppUninstall(appUninstallEntry{}); err == nil {
		t.Fatal("empty command accepted")
	}
}

func TestAppPlannerExpandsWindowsEnvironmentVariables(t *testing.T) {
	dir, err := windowsPkg.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_TEST_UNINSTALL_SYSTEM", dir)
	plan, err := planAppUninstall(appUninstallEntry{UninstallString: "\"%WARDEN_TEST_UNINSTALL_SYSTEM%\\msiexec.exe\" /I" + appTestGUID})
	if err != nil || !strings.EqualFold(plan.Executable, filepath.Join(dir, "msiexec.exe")) {
		t.Fatal(plan, err)
	}
}
