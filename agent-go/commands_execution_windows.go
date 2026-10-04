package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const maxCommandOutputBytes = 1024 * 1024

type cappedCommandOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (w *cappedCommandOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	originalLength := len(p)
	remaining := maxCommandOutputBytes - len(w.data)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.data = append(w.data, p...)
	}
	if originalLength > remaining {
		w.truncated = true
	}
	return originalLength, nil
}

func (w *cappedCommandOutput) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := append([]byte(nil), w.data...)
	if w.truncated {
		result = append(result, []byte("\n[Warden truncated command output after 1 MiB]")...)
	}
	return result
}

func boundedCombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	output := &cappedCommandOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	err := runCommandInKillJob(cmd)
	return output.Bytes(), err
}

// ── System commands ───────────────────────────────────────────────────────────

var runCmdWhitelist = map[string][]string{
	"system_info": {
		"powershell", "-NonInteractive", "-Command",
		"Get-ComputerInfo | Select-Object OsName,OsVersion,CsName,CsProcessors | ConvertTo-Json",
	},
	"powershell_get_info": {
		"powershell", "-NonInteractive", "-Command",
		"Get-ComputerInfo | Select-Object OsName,OsVersion,CsName,CsProcessors | ConvertTo-Json",
	},
	"clear_temp": {"cmd", "/c", "del", "/q", "/f", "/s", `C:\Windows\Temp\*`},
	"flush_dns":  {"ipconfig", "/flushdns"},
	"check_disk": {"chkdsk", "C:", "/scan"},
	"sync_time": {
		"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
		"Set-Service -Name w32time -StartupType Automatic -ErrorAction Stop; Start-Service -Name w32time -ErrorAction Stop; w32tm.exe /resync /force",
	},
	"clock_status": {
		"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
		"[ordered]@{ UtcTime = [DateTime]::UtcNow.ToString('o'); LocalTime = [DateTime]::Now.ToString('o'); TimeZone = (Get-TimeZone).Id; TimeSource = ((w32tm.exe /query /source) -join '').Trim() } | ConvertTo-Json -Compress",
	},
}

func runCmdJob(p map[string]interface{}) (int, string, error) {
	cmdType, _ := p["cmd_type"].(string)
	args, ok := runCmdWhitelist[cmdType]
	if !ok {
		return 1, "", fmt.Errorf("cmd_type '%s' not in whitelist", cmdType)
	}
	timeout := 60 * time.Second
	if cmdType == "check_disk" {
		timeout = 300 * time.Second
	}
	cmd := exec.Command(args[0], args[1:]...)
	type commandResult struct {
		out []byte
		err error
	}
	done := make(chan commandResult, 1)
	go func() {
		out, err := boundedCombinedOutput(cmd)
		done <- commandResult{out: out, err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			code := 1
			if exitErr, ok := result.err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			}
			return code, string(result.out), result.err
		}
		return 0, string(result.out), nil
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return 1, "", fmt.Errorf("command timed out")
	}
}

func reboot(p map[string]interface{}) (int, string, error) {
	delay := 30
	if d, ok := p["delay_seconds"].(float64); ok {
		delay = int(d)
	}
	out, err := exec.Command("shutdown", "/r", "/t", strconv.Itoa(delay), "/c", "Warden Agent: Scheduled reboot").CombinedOutput()
	if err != nil {
		return commandExitCode(err), string(out), fmt.Errorf("schedule reboot: %w", err)
	}
	return 0, fmt.Sprintf("Reboot scheduled in %d seconds", delay), nil
}

func shutdown(p map[string]interface{}) (int, string, error) {
	delay := 30
	if d, ok := p["delay_seconds"].(float64); ok {
		delay = int(d)
	}
	out, err := exec.Command("shutdown", "/s", "/t", strconv.Itoa(delay), "/c", "Warden Agent: Scheduled shutdown").CombinedOutput()
	if err != nil {
		return commandExitCode(err), string(out), fmt.Errorf("schedule shutdown: %w", err)
	}
	return 0, fmt.Sprintf("Shutdown scheduled in %d seconds", delay), nil
}

const reaperScriptTemplate = `@echo off
ping -n 6 127.0.0.1 >nul
sc stop "%s" >nul 2>&1
set /a wait_count=0
:waitloop
powershell -NoProfile -NonInteractive -Command "$s = Get-Service -Name '%s' -ErrorAction SilentlyContinue; if (-not $s -or $s.Status -eq 'Stopped') { exit 0 } else { exit 1 }"
if not errorlevel 1 goto stopped
set /a wait_count+=1
if %%wait_count%% geq 150 goto stopped
ping -n 3 127.0.0.1 >nul
goto waitloop
:stopped
sc delete "%s" >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{7C0EAF41-2D67-4F6B-A562-6BF97BD19EE1}" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Classes\CLSID\{7C0EAF41-2D67-4F6B-A562-6BF97BD19EE1}" /f >nul 2>&1
icacls "%s" /reset /T >nul 2>&1
icacls "%s" /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" >nul 2>&1
rmdir /s /q "%s" >nul 2>&1
icacls "%s" /reset /T >nul 2>&1
icacls "%s" /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" >nul 2>&1
rmdir /s /q "%s" >nul 2>&1
icacls "%s" /reset /T >nul 2>&1
icacls "%s" /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" >nul 2>&1
rmdir /s /q "%s" >nul 2>&1
(goto) 2>nul & del "%%~f0"
`

// performSelfRemoval is only reachable via a job that already passed
// Ed25519 signature + nonce verification in the normal dispatch path (or the
// equivalent check in the `uninstall` CLI command in main.go) — i.e. an
// admin-approved, dual-approval-gated UNINSTALL_AGENT job.
func performSelfRemoval() (int, string, error) {
	if err := unlockService(); err != nil {
		logWarn("unlockService before removal failed (continuing): %v", err)
	}
	script := fmt.Sprintf(reaperScriptTemplate,
		serviceName, serviceName, serviceName,
		wardenCredentialProviderDir, wardenCredentialProviderDir, wardenCredentialProviderDir,
		dataDir, dataDir, dataDir,
		installDir, installDir, installDir,
	)
	scriptPath := filepath.Join(os.Getenv("WINDIR"), "Temp", "warden-uninstall.bat")
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return 1, "", fmt.Errorf("write reaper script: %w", err)
	}
	cmd := exec.Command("cmd.exe", "/c", scriptPath)
	cmd.Dir = filepath.Dir(scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	}
	if err := cmd.Start(); err != nil {
		return 1, "", fmt.Errorf("start reaper script: %w", err)
	}
	selfRemovalScheduled.Store(true)
	logInfo("Self-removal scheduled; agent will be gone within a few seconds")
	return 0, "Agent uninstall scheduled", nil
}

// runCmd is a fire-and-forget helper for simple commands (e.g., icacls).
func runCmd(name string, args ...string) {
	exec.Command(name, args...).Run()
}

func commandExitCode(err error) int {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}
