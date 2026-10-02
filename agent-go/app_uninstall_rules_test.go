package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const appTestGUID = "{12345678-1234-1234-1234-123456789ABC}"

func TestAppUninstallPrefersRegisteredQuietCommand(t *testing.T) {
	e := appUninstallEntry{UninstallString: "normal.exe", QuietUninstallString: "quiet.exe /vendorflag"}
	command, quiet := registeredAppUninstallCommand(e)
	if command != "quiet.exe /vendorflag" || !quiet {
		t.Fatalf("wrong selection %q %v", command, quiet)
	}
}
func TestAppUninstallFallsBackToNormalCommand(t *testing.T) {
	command, quiet := registeredAppUninstallCommand(appUninstallEntry{UninstallString: "normal.exe /S"})
	if command != "normal.exe /S" || quiet {
		t.Fatal(command, quiet)
	}
}
func TestAppUninstallSynthesizesOnlyRegisteredMSIGUID(t *testing.T) {
	command, _ := registeredAppUninstallCommand(appUninstallEntry{KeyName: appTestGUID, WindowsInstaller: true})
	if command != "msiexec.exe /x "+appTestGUID {
		t.Fatal(command)
	}
	for _, e := range []appUninstallEntry{{KeyName: appTestGUID}, {KeyName: "invalid", WindowsInstaller: true}} {
		if command, _ := registeredAppUninstallCommand(e); command != "" {
			t.Fatal("guessed MSI target", command)
		}
	}
}
func TestCPUZInnoUninstallIsSilentAndNeverReboots(t *testing.T) {
	e := appUninstallEntry{KeyName: "CPUID CPU-Z_is1", DisplayName: "CPUID CPU-Z 2.18"}
	args, mode, err := appUninstallArgs(e, "C:\\Program Files\\CPUID\\CPU-Z\\unins000.exe", nil, false)
	if err != nil || !strings.HasPrefix(mode, "Inno Setup") {
		t.Fatal(mode, err)
	}
	if !reflect.DeepEqual(args, []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"}) {
		t.Fatal(args)
	}
}
func TestAppInnoSwitchesNormalizedWithoutDuplicates(t *testing.T) {
	args, _, err := appUninstallArgs(appUninstallEntry{KeyName: "app_IS1"}, "unins001.EXE",
		[]string{"/silent", "/NORESTART", "/VERYSILENT", "/suppressmsgboxes", "/LOG"}, true)
	if err != nil || !reflect.DeepEqual(args, []string{"/LOG", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"}) {
		t.Fatal(args, err)
	}
}
func TestAppUninstallNeverGuessesInnoFromNameAlone(t *testing.T) {
	for _, e := range []appUninstallEntry{{KeyName: "other"}, {KeyName: "app_is1"}} {
		exe := "unins000.exe"
		if e.KeyName == "app_is1" {
			exe = "unknown.exe"
		}
		if _, _, err := appUninstallArgs(e, exe, nil, false); err == nil {
			t.Fatal("guessed uninstaller", e)
		}
	}
}
func TestAppUnknownInteractiveUninstallerFailsImmediately(t *testing.T) {
	_, _, err := appUninstallArgs(appUninstallEntry{DisplayName: "Unknown"}, "uninstall.exe", nil, false)
	if err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatal(err)
	}
}
func TestAppRegisteredQuietCommandPreservesVendorArguments(t *testing.T) {
	input := []string{"-vendor-mode", "argument with spaces"}
	args, _, err := appUninstallArgs(appUninstallEntry{}, "vendor.exe", input, true)
	if err != nil || !reflect.DeepEqual(args, input) {
		t.Fatal(args, err)
	}
	args[0] = "modified"
	if input[0] == "modified" {
		t.Fatal("mutated source arguments")
	}
}
func TestAppExistingRegisteredSilentSwitchPreserved(t *testing.T) {
	for _, flag := range []string{"/S", "/quiet", "/silent", "--silent", "-s", "/qn"} {
		if _, _, err := appUninstallArgs(appUninstallEntry{}, "vendor.exe", []string{flag}, false); err != nil {
			t.Fatal(flag, err)
		}
	}
}
func TestAppVendorRestartRequestRejected(t *testing.T) {
	for _, flag := range []string{"/forcerestart", "/restart", "/reboot", "REBOOT=Force"} {
		if _, _, err := appUninstallArgs(appUninstallEntry{}, "vendor.exe", []string{flag}, true); err == nil {
			t.Fatal("restart allowed", flag)
		}
	}
}
func TestAppInnoRestartRequestRejected(t *testing.T) {
	if _, _, err := appUninstallArgs(appUninstallEntry{KeyName: "app_is1"}, "unins000.exe", []string{"/RESTART"}, false); err == nil {
		t.Fatal("restart allowed")
	}
}
func TestMSIUninstallConvertsMaintenanceToRemoval(t *testing.T) {
	for _, input := range [][]string{{"/I" + appTestGUID}, {"/I", appTestGUID}, {"/x", appTestGUID}, {"/uninstall", appTestGUID}, {"/package", appTestGUID}} {
		args, err := msiUninstallArgs(input)
		if err != nil || !reflect.DeepEqual(args, []string{"/x", appTestGUID, "/quiet", "/norestart", "REBOOT=ReallySuppress"}) {
			t.Fatal(input, args, err)
		}
	}
}
func TestMSIUninstallAlwaysSuppressesRestartAndUI(t *testing.T) {
	args, err := msiUninstallArgs([]string{"/x", appTestGUID, "/qn", "/forcerestart", "REBOOT=Force", "REBOOTPROMPT=anything"})
	if err != nil || !reflect.DeepEqual(args, []string{"/x", appTestGUID, "/quiet", "/norestart", "REBOOT=ReallySuppress"}) {
		t.Fatal(args, err)
	}
}

func TestMSIUninstallTargetMustMatchRegistration(t *testing.T) {
	entry := appUninstallEntry{WindowsInstaller: true, KeyName: "{AAAAAAAA-1234-1234-1234-123456789ABC}"}
	if _, _, err := appUninstallArgs(entry, "msiexec.exe", []string{"/x", appTestGUID}, false); err == nil {
		t.Fatal("different registered product target accepted")
	}
}

func TestAppUninstallNonzeroCodeCannotBecomeSuccess(t *testing.T) {
	code, _, err := appUninstallResult("vendor", 1603, "", nil, false, false, nil, 300)
	if code == 0 || err == nil {
		t.Fatal("nonzero process exit accepted")
	}
}
func TestMSIRejectsMissingMalformedAndMultipleTargets(t *testing.T) {
	for _, input := range [][]string{nil, {"/x"}, {"/x", "bad"}, {"/x", "C:\\fake.msi"}, {"/x", appTestGUID, "/i", appTestGUID}, {"/x", appTestGUID, "/y", "evil.dll"}} {
		if _, err := msiUninstallArgs(input); err == nil {
			t.Fatal("unsafe MSI invocation accepted", input)
		}
	}
}
func TestAppRegistrationSelectionRejectsAmbiguity(t *testing.T) {
	for _, entries := range [][]appUninstallEntry{nil, {{DisplayName: "app"}, {DisplayName: "app"}}} {
		if _, err := selectAppUninstallEntry("app", entries); err == nil {
			t.Fatal("ambiguous or missing selection accepted")
		}
	}
}
func TestAppRegistrationSelectionReturnsExactEntry(t *testing.T) {
	input := appUninstallEntry{DisplayName: "app", KeyName: "unique"}
	if result, err := selectAppUninstallEntry("app", []appUninstallEntry{input}); err != nil || result.KeyName != "unique" {
		t.Fatal(result, err)
	}
}
func TestAppUninstallSuccessfulExitRequiresRemovalVerification(t *testing.T) {
	code, _, err := appUninstallResult("vendor", 0, "", nil, false, true, nil, 300)
	if code == 0 || err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatal(code, err)
	}
}
func TestAppUninstallClearedRegistrationIsConfirmed(t *testing.T) {
	code, out, err := appUninstallResult("vendor", 0, "", nil, false, false, nil, 300)
	if code != 0 || err != nil || !strings.Contains(out, "Removal confirmed") {
		t.Fatal(code, out, err)
	}
}
func TestAppUninstallVerificationFailureCannotBecomeSuccess(t *testing.T) {
	code, _, err := appUninstallResult("vendor", 0, "", nil, false, false, errors.New("access denied"), 300)
	if code == 0 || err == nil {
		t.Fatal(code, err)
	}
}
func TestAppUninstallTimeoutIsNotRemovalSuccess(t *testing.T) {
	code, _, err := appUninstallResult("vendor", 1, "", errors.New("killed"), true, false, nil, 300)
	if code == 0 || err == nil || !strings.Contains(err.Error(), "300 seconds") || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatal(code, err)
	}
}
func TestAppUninstallPreservesFailureExitCodeInError(t *testing.T) {
	code, _, err := appUninstallResult("vendor", 1603, "", errors.New("process failed"), false, false, nil, 300)
	if code == 0 || err == nil || !strings.Contains(err.Error(), "1603") {
		t.Fatal(code, err)
	}
}
func TestMSIRestartRequiredReportedWithoutClaimingRemoval(t *testing.T) {
	code, out, err := appUninstallResult("Windows Installer (silent, no restart)", 3010, "", errors.New("exit 3010"), false, true, nil, 300)
	if code != 0 || err != nil || !strings.Contains(out, "registration remains present") || !strings.Contains(out, "no restart was triggered") || strings.Contains(out, "Removal confirmed") {
		t.Fatal(code, out, err)
	}
}
func TestMSIRestartRequiredWithClearedRegistration(t *testing.T) {
	code, out, err := appUninstallResult("Windows Installer (silent, no restart)", 3010, "", errors.New("exit 3010"), false, false, nil, 300)
	if code != 0 || err != nil || !strings.Contains(out, "restart required") {
		t.Fatal(code, out, err)
	}
}
func TestAppNonMSIRestartCodeNotTreatedAsSuccess(t *testing.T) {
	code, _, err := appUninstallResult("vendor", 3010, "", errors.New("exit 3010"), false, false, nil, 300)
	if code == 0 || err == nil {
		t.Fatal(code, err)
	}
}
