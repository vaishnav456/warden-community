package main

// Pure uninstall planning/result rules, also exercised without Windows registry access.
import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type appUninstallEntry struct {
	Hive                                                                 uintptr
	KeyPath, KeyName, DisplayName, UninstallString, QuietUninstallString string
	WindowsInstaller                                                     bool
}
type appUninstallPlan struct {
	Executable string
	Args       []string
	Mode       string
}

var uninstallGUID = regexp.MustCompile("(?i)^\\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\}$")
var innoUninstallerName = regexp.MustCompile("(?i)^unins[0-9]{3}\\.exe$")

func registeredAppUninstallCommand(entry appUninstallEntry) (string, bool) {
	if entry.QuietUninstallString != "" {
		return entry.QuietUninstallString, true
	}
	if entry.UninstallString != "" {
		return entry.UninstallString, false
	}
	if entry.WindowsInstaller && uninstallGUID.MatchString(entry.KeyName) {
		return "msiexec.exe /x " + entry.KeyName, false
	}
	return "", false
}
func selectAppUninstallEntry(name string, entries []appUninstallEntry) (appUninstallEntry, error) {
	if len(entries) == 0 {
		return appUninstallEntry{}, fmt.Errorf("product %q not found in uninstall registry; no removal was started", name)
	}
	if len(entries) != 1 {
		return appUninstallEntry{}, fmt.Errorf("multiple registrations match %q; no removal was started", name)
	}
	return entries[0], nil
}
func appUninstallArgs(entry appUninstallEntry, executable string, args []string, quiet bool) ([]string, string, error) {
	base := strings.ToLower(path.Base(strings.ReplaceAll(executable, "\\", "/")))
	if base == "msiexec.exe" || base == "msiexec" {
		normalized, err := msiUninstallArgs(args)
		if err == nil && entry.WindowsInstaller && uninstallGUID.MatchString(entry.KeyName) && !strings.EqualFold(normalized[1], entry.KeyName) {
			return nil, "", fmt.Errorf("Windows Installer command does not match the selected registered product; no removal was started")
		}
		return normalized, "Windows Installer (silent, no restart)", err
	}
	inno := strings.HasSuffix(strings.ToLower(entry.KeyName), "_is1") && innoUninstallerName.MatchString(base)
	if inno {
		result := make([]string, 0, len(args)+3)
		for _, arg := range args {
			switch strings.ToLower(arg) {
			case "/silent", "/verysilent", "/suppressmsgboxes", "/norestart":
				continue
			case "/restart", "/forcerestart", "/reboot":
				return nil, "", fmt.Errorf("registered uninstall command requests a restart; no removal was started")
			}
			result = append(result, arg)
		}
		return append(result, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"), "Inno Setup (silent, no restart)", nil
	}
	// A vendor's registered quiet command is authoritative. For normal strings,
	// accept an existing silent switch, but never invent /S for an unknown EXE.
	silent := quiet
	for _, arg := range args {
		switch strings.ToLower(arg) {
		case "/quiet", "/silent", "/verysilent", "/qn", "/s", "-s", "--silent", "--quiet":
			silent = true
		case "/forcerestart", "/restart", "/reboot", "reboot=force":
			return nil, "", fmt.Errorf("registered uninstall command requests a restart; no removal was started")
		}
	}
	if !silent {
		return nil, "", fmt.Errorf("no supported silent uninstall command is registered for %q; unattended removal was not started", entry.DisplayName)
	}
	return append([]string(nil), args...), "vendor-registered silent command", nil
}
func msiUninstallArgs(args []string) ([]string, error) {
	// Rebuild for the registered product code, preventing /I maintenance UI,
	// conflicting UI switches, and automatic restart.
	target := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		lower := strings.ToLower(arg)
		switch {
		case lower == "/i" || lower == "/x" || lower == "/package" || lower == "/uninstall":
			if i+1 >= len(args) || target != "" {
				return nil, fmt.Errorf("invalid Windows Installer removal target")
			}
			i++
			target = args[i]
		case strings.HasPrefix(lower, "/i{") || strings.HasPrefix(lower, "/x{"):
			if target != "" {
				return nil, fmt.Errorf("multiple Windows Installer removal targets")
			}
			target = arg[2:]
		case lower == "/quiet" || lower == "/passive" || lower == "/norestart" || lower == "/forcerestart" || lower == "/promptrestart" || strings.HasPrefix(lower, "/q"):
		case strings.HasPrefix(lower, "reboot=") || strings.HasPrefix(lower, "rebootprompt="):
		default:
			return nil, fmt.Errorf("unsupported Windows Installer removal option; no removal was started")
		}
	}
	if !uninstallGUID.MatchString(target) {
		return nil, fmt.Errorf("Windows Installer uninstall requires a registered product GUID; no removal was started")
	}
	return []string{"/x", target, "/quiet", "/norestart", "REBOOT=ReallySuppress"}, nil
}
func appUninstallResult(mode string, code int, output string, runErr error, timedOut bool, present bool, verifyErr error, timeoutSeconds int) (int, string, error) {
	output = "Uninstall mode: " + mode + "\n" + output
	if timedOut {
		return 1, output, fmt.Errorf("uninstall timed out after %d seconds; removal is not confirmed; check the application's registered uninstaller", timeoutSeconds)
	}
	restartRequired := strings.HasPrefix(mode, "Windows Installer") && code == 3010
	if (runErr != nil || code != 0) && !restartRequired {
		if runErr == nil {
			runErr = fmt.Errorf("nonzero process exit")
		}
		return 1, output, fmt.Errorf("uninstall failed (exit %d): %w", code, runErr)
	}
	if verifyErr != nil {
		return 1, output, fmt.Errorf("uninstaller finished but registry verification failed; removal is not confirmed: %w", verifyErr)
	}
	if present {
		if restartRequired {
			return 0, output + "\nWindows Installer reports a restart is required to finish removal. The registration remains present; no restart was triggered.", nil
		}
		return 1, output, fmt.Errorf("uninstaller exited successfully but the application's uninstall registration remains present; removal is not confirmed")
	}
	if restartRequired {
		output += "\nRemoval registration cleared. Windows Installer reports restart required; no restart was triggered."
	} else {
		output += "\nRemoval confirmed: the selected uninstall registration is no longer present."
	}
	return 0, output, nil
}
