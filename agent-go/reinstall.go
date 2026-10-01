package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const reinstallRoot = `C:\ProgramData\WardenReinstall`

// Called only after envelope signature validation. A downgrade additionally
// binds the administrator's rollback authorization to the installed version.
func validateReinstallVersion(version string, p map[string]interface{}) error {
	cmp, err := compareAgentVersions(version, agentVersion)
	if err != nil {
		return fmt.Errorf("invalid reinstall version: %w", err)
	}
	if cmp < 0 && p["rollback_from"] != agentVersion {
		return fmt.Errorf("agent downgrade from %s to %s is not allowed", agentVersion, version)
	}
	return nil
}

func prepareAgentReinstall(jobID string, p map[string]interface{}) (int, string, error) {
	relayMu.Lock()
	remoteActive := relayLive != nil
	relayMu.Unlock()
	if remoteActive {
		return 1, "", fmt.Errorf("agent reinstall refused while remote access is active; disconnect the remote session and retry")
	}

	downloadURL, _ := p["download_url"].(string)
	expectedSHA256, _ := p["sha256"].(string)
	version, _ := p["version"].(string)
	providerURL, _ := p["credential_provider_url"].(string)
	providerSHA256, _ := p["credential_provider_sha256"].(string)
	if downloadURL == "" {
		return 1, "", fmt.Errorf("missing download_url")
	}
	if providerURL == "" || providerSHA256 == "" {
		return 1, "", fmt.Errorf("Windows reinstall is missing its Credential Provider artifact")
	}
	if err := validateReinstallVersion(version, p); err != nil {
		return 1, "", err
	}

	handoffDir := filepath.Join(reinstallRoot, strings.ToLower(jobID))
	if err := createSystemOnlyDirectory(handoffDir); err != nil {
		return 1, "", fmt.Errorf("secure reinstall handoff: %w", err)
	}
	replacementPath := filepath.Join(handoffDir, "warden-agent-new.exe")
	if err := downloadFile(downloadURL, replacementPath, expectedSHA256); err != nil {
		return 1, "", fmt.Errorf("download replacement agent: %w", err)
	}
	requireSignature := requireAuthenticodeUpdates()
	if requested, ok := p["require_authenticode"].(bool); ok && requested {
		requireSignature = true
	}
	if err := verifyExecutionArtifact(replacementPath, expectedSHA256, requireSignature); err != nil {
		return 1, "", fmt.Errorf("replacement agent verification failed: %w", err)
	}
	providerPath := filepath.Join(handoffDir, wardenCredentialProviderAsset)
	if err := downloadFile(providerURL, providerPath, providerSHA256); err != nil {
		return 1, "", fmt.Errorf("download Credential Provider: %w", err)
	}
	if err := verifyExecutionArtifact(providerPath, providerSHA256, requireSignature); err != nil {
		return 1, "", fmt.Errorf("Credential Provider verification failed: %w", err)
	}

	currentExe, err := os.Executable()
	if err != nil {
		return 1, "", fmt.Errorf("locate running agent: %w", err)
	}
	helperPath := filepath.Join(handoffDir, "warden-reinstall-helper.exe")
	if err := copyFile(currentExe, helperPath); err != nil {
		return 1, "", fmt.Errorf("stage reinstall helper: %w", err)
	}
	helperHash, err := fileSHA256(currentExe)
	if err != nil {
		return 1, "", fmt.Errorf("hash running agent: %w", err)
	}
	if err := verifyExecutionArtifact(helperPath, helperHash, requireSignature); err != nil {
		return 1, "", fmt.Errorf("reinstall helper verification failed: %w", err)
	}

	taskName := "Warden-Reinstall-" + strings.ToLower(jobID)
	helperArgs := strings.Join([]string{
		"--reinstall-helper", strings.ToLower(jobID),
		strings.ToLower(expectedSHA256), helperHash, strconv.FormatBool(requireSignature), version,
		strings.ToLower(providerSHA256),
	}, " ")
	// Task Scheduler caps /TR at 261 characters. Two artifact hashes plus the
	// helper hash exceed that limit, so keep the registered action short and
	// put the full, SYSTEM-only handoff command inside the protected directory.
	runnerPath := filepath.Join(handoffDir, "run-reinstall.cmd")
	statusPath := filepath.Join(dataDir, "reinstall-status-"+strings.ToLower(jobID)+".log")
	_ = os.Remove(statusPath)
	runnerContent := fmt.Sprintf(
		"@echo off\r\necho %%DATE%% %%TIME%% Reinstall runner started>\"%s\"\r\n\"%s\" %s\r\nset WARDEN_REINSTALL_EXIT=%%errorlevel%%\r\ndel /q \"%s\" >nul 2>&1\r\ndel /q \"%%~f0\" >nul 2>&1\r\nexit /b %%WARDEN_REINSTALL_EXIT%%\r\n",
		statusPath, helperPath, helperArgs, helperPath,
	)
	if err := os.WriteFile(runnerPath, []byte(runnerContent), 0600); err != nil {
		return 1, "", fmt.Errorf("write reinstall handoff script: %w", err)
	}
	// schtasks /Create's CLI defaults prohibit starting on battery power,
	// which leaves laptop reinstalls queued indefinitely. An explicit task XML
	// keeps the reboot-persistent SYSTEM handoff while allowing it on battery.
	taskXMLPath := filepath.Join(handoffDir, "reinstall-task.xml")
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Warden</Author></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled><Hidden>true</Hidden><WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit><Priority>4</Priority>
  </Settings>
  <Actions Context="System"><Exec><Command>C:\Windows\System32\cmd.exe</Command><Arguments>/d /c ""%s""</Arguments></Exec></Actions>
</Task>`, runnerPath)
	if err := os.WriteFile(taskXMLPath, encodeUTF16LE(taskXML), 0600); err != nil {
		return 1, "", fmt.Errorf("write reinstall task definition: %w", err)
	}
	createOut, err := exec.Command(
		"schtasks.exe", "/Create", "/TN", taskName,
		"/XML", taskXMLPath, "/F",
	).CombinedOutput()
	if err != nil {
		return 1, string(createOut), fmt.Errorf("create persistent reinstall handoff task: %w", err)
	}
	runOut, err := exec.Command("schtasks.exe", "/Run", "/TN", taskName).CombinedOutput()
	if err != nil {
		return 1, string(runOut), fmt.Errorf("start persistent reinstall handoff task: %w", err)
	}
	// `/Run` only confirms that Task Scheduler accepted the request; it can
	// still fail to launch the action. Do not report success until the runner
	// itself creates its SYSTEM-only marker.
	runnerStarted := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if _, statErr := os.Stat(statusPath); statErr == nil {
			runnerStarted = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !runnerStarted {
		queryOut, _ := exec.Command(
			"schtasks.exe", "/Query", "/TN", taskName, "/V", "/FO", "LIST",
		).CombinedOutput()
		_ = exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
		return 1, string(queryOut), fmt.Errorf("reinstall handoff task was accepted but its runner did not start")
	}

	return 0, fmt.Sprintf("Verified agent %s update handoff started; service restart scheduled", version), nil
}

// Task Scheduler's /XML importer requires a native Unicode file for this
// import path. Match schtasks.exe output with UTF-16LE and a byte-order mark.
func encodeUTF16LE(value string) []byte {
	words := utf16.Encode([]rune(value))
	encoded := make([]byte, 2+len(words)*2)
	encoded[0], encoded[1] = 0xff, 0xfe
	for i, word := range words {
		encoded[2+i*2] = byte(word)
		encoded[3+i*2] = byte(word >> 8)
	}
	return encoded
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runReinstallHelper(jobID, expectedSHA256, expectedHelperSHA256 string, requireSignature bool, expectedVersion, providerSHA256 string) int {
	if !canonicalJobID.MatchString(jobID) || len(expectedSHA256) != 64 || len(expectedHelperSHA256) != 64 || len(providerSHA256) != 64 {
		return 2
	}
	handoffDir := filepath.Join(reinstallRoot, strings.ToLower(jobID))
	replacementPath := filepath.Join(handoffDir, "warden-agent-new.exe")
	backupPath := filepath.Join(handoffDir, "warden-agent-backup.exe")
	providerPath := filepath.Join(handoffDir, wardenCredentialProviderAsset)
	providerAssetPath := filepath.Join(filepath.Dir(installedExePath), wardenCredentialProviderAsset)
	providerBackupPath := filepath.Join(handoffDir, "WardenCredentialProvider-backup.dll")
	taskXMLPath := filepath.Join(handoffDir, "reinstall-task.xml")
	logPath := filepath.Join(handoffDir, "reinstall.log")
	statusPath := filepath.Join(dataDir, "reinstall-status-"+strings.ToLower(jobID)+".log")
	taskName := "Warden-Reinstall-" + strings.ToLower(jobID)
	deleteTask := func() {
		_ = exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
	}
	writeLog := func(message string) {
		line := []byte(time.Now().UTC().Format(time.RFC3339) + " " + message + "\r\n")
		for _, path := range []string{logPath, statusPath} {
			if file, openErr := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); openErr == nil {
				_, _ = file.Write(line)
				_ = file.Close()
			}
		}
	}
	writeLog("Reinstall helper started")
	currentExe, err := os.Executable()
	if err != nil || verifyExecutionArtifact(currentExe, expectedHelperSHA256, requireSignature) != nil {
		writeLog("Reinstall helper integrity verification failed closed")
		deleteTask()
		return 6
	}

	// Give the service time to report the accepted job before interrupting its
	// heartbeat loop. The persistent task survives a reboot if Windows goes
	// down during this handoff.
	time.Sleep(8 * time.Second)
	if err := unlockService(); err != nil {
		writeLog("Could not unlock service for update: " + err.Error())
		deleteTask()
		return 3
	}
	if err := stopServiceAndWait(45 * time.Second); err != nil {
		writeLog("Could not stop service for update: " + err.Error())
		applyTamperProtection()
		deleteTask()
		return 3
	}
	if err := verifyExecutionArtifact(replacementPath, expectedSHA256, requireSignature); err != nil {
		writeLog("Replacement verification failed closed: " + err.Error())
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 4
	}
	if err := verifyExecutionArtifact(providerPath, providerSHA256, requireSignature); err != nil {
		writeLog("Credential Provider verification failed closed: " + err.Error())
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 4
	}
	providerPreviouslyPresent := false
	if info, statErr := os.Stat(providerAssetPath); statErr == nil && !info.IsDir() {
		providerPreviouslyPresent = true
		if err := copyFile(providerAssetPath, providerBackupPath); err != nil {
			writeLog("Could not back up Credential Provider: " + err.Error())
			_ = startService()
			applyTamperProtection()
			deleteTask()
			return 5
		}
	}
	restoreProvider := func() {
		if providerPreviouslyPresent {
			_ = copyFile(providerBackupPath, providerAssetPath)
		} else {
			_ = os.Remove(providerAssetPath)
		}
	}
	if err := copyFile(installedExePath, backupPath); err != nil {
		writeLog("Could not create rollback copy: " + err.Error())
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 5
	}
	if err := copyFile(replacementPath, installedExePath); err != nil {
		writeLog("Could not replace installed agent: " + err.Error())
		_ = copyFile(backupPath, installedExePath)
		restoreProvider()
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 5
	}
	if err := copyFile(providerPath, providerAssetPath); err != nil {
		writeLog("Could not replace Credential Provider asset: " + err.Error())
		_ = copyFile(backupPath, installedExePath)
		restoreProvider()
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 5
	}
	if err := verifyExecutionArtifact(providerAssetPath, providerSHA256, requireSignature); err != nil {
		writeLog("Installed Credential Provider asset failed verification: " + err.Error())
		_ = copyFile(backupPath, installedExePath)
		restoreProvider()
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 5
	}
	if err := verifyExecutionArtifact(installedExePath, expectedSHA256, requireSignature); err != nil {
		writeLog("Installed replacement failed final verification: " + err.Error())
		_ = copyFile(backupPath, installedExePath)
		restoreProvider()
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 5
	}
	_ = os.Remove(updateHealthPath)
	if err := startService(); err != nil {
		writeLog("Replacement service did not start; rolling back: " + err.Error())
		_ = copyFile(backupPath, installedExePath)
		restoreProvider()
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 5
	}
	deadline := time.Now().Add(75 * time.Second)
	healthy := false
	for time.Now().Before(deadline) {
		if marker, err := os.ReadFile(updateHealthPath); err == nil && strings.TrimSpace(string(marker)) == expectedVersion {
			healthy = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !healthy {
		writeLog("Replacement did not become healthy; rolling back")
		_ = unlockService()
		_ = stopServiceAndWait(30 * time.Second)
		_ = copyFile(backupPath, installedExePath)
		restoreProvider()
		_ = os.Remove(updateHealthPath)
		_ = startService()
		applyTamperProtection()
		deleteTask()
		return 5
	}
	writeLog("Agent update completed successfully")
	applyTamperProtection()
	deleteTask()
	_ = os.Remove(replacementPath)
	_ = os.Remove(backupPath)
	_ = os.Remove(providerPath)
	_ = os.Remove(providerBackupPath)
	_ = os.Remove(taskXMLPath)
	return 0
}
