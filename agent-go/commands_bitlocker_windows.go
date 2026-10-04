package main

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

// ── BitLocker encryption and tenant recovery-key escrow ─────────────────────

type bitLockerProtector struct {
	MountPoint        string   `json:"mount_point"`
	ProtectorID       string   `json:"protector_id"`
	RecoveryPassword  string   `json:"recovery_password"`
	OldRecoveryIDs    []string `json:"old_recovery_ids"`
	VolumeStatus      string   `json:"volume_status"`
	ProtectionStatus  string   `json:"protection_status"`
	EncryptionPercent float64  `json:"encryption_percentage"`
}

const prepareBitLockerScript = `$ErrorActionPreference='Stop'
$mount=$env:SystemDrive
if (-not $mount) { throw 'Windows system drive is unavailable' }
$volume=Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop
$old=@($volume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'})
Add-BitLockerKeyProtector -MountPoint $mount -RecoveryPassword $env:WARDEN_RECOVERY_PASSWORD -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
# Add-BitLockerKeyProtector can return a stale/incomplete BitLockerVolume on
# some Windows builds. Query the volume again before locating the protector.
$refreshed=Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop
$selected=@($refreshed.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.RecoveryPassword -eq $env:WARDEN_RECOVERY_PASSWORD})[0]
if (-not $selected) { throw 'Windows did not return the newly-created recovery protector' }
[pscustomobject]@{
 mount_point=$mount; protector_id=[string]$selected.KeyProtectorId
 old_recovery_ids=@($old | Where-Object {$_.KeyProtectorId -ne $selected.KeyProtectorId} | ForEach-Object {[string]$_.KeyProtectorId})
 volume_status=[string]$refreshed.VolumeStatus; protection_status=[string]$refreshed.ProtectionStatus
 encryption_percentage=[double]$refreshed.EncryptionPercentage
} | ConvertTo-Json -Compress`

const readBitLockerStatusScript = `$ErrorActionPreference='Stop'; $v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; [pscustomobject]@{volume_status=[string]$v.VolumeStatus; protection_status=[string]$v.ProtectionStatus; encryption_percentage=[double]$v.EncryptionPercentage} | ConvertTo-Json -Compress`
const removeBitLockerRecoveryByPasswordScript = `$ErrorActionPreference='Stop'; $v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; @($v.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and $_.RecoveryPassword -eq $env:WARDEN_RECOVERY_PASSWORD}) | ForEach-Object { Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId -ErrorAction Stop }`

func generateBitLockerRecoveryPassword() (string, error) {
	// A BitLocker numerical password is eight six-digit groups. Each group is
	// one of 65,536 values multiplied by 11 (000000 through 720885).
	groups := make([]string, 8)
	limit := big.NewInt(65536)
	for index := range groups {
		value, err := cryptoRand.Int(cryptoRand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("generate recovery password: %w", err)
		}
		groups[index] = fmt.Sprintf("%06d", value.Int64()*11)
	}
	return strings.Join(groups, "-"), nil
}

func normalizePowerShellOutput(output []byte) []byte {
	output = bytes.TrimSpace(output)
	if len(output) < 2 {
		return output
	}
	// Windows PowerShell can switch redirected native stdout to UTF-16LE.
	// Decode it before JSON parsing; the recovery password itself is never
	// printed by our scripts.
	utf16LE := output[0] == 0xff && output[1] == 0xfe
	if !utf16LE {
		nulls := 0
		for index := 1; index < len(output); index += 2 {
			if output[index] == 0 {
				nulls++
			}
		}
		utf16LE = nulls > len(output)/6
	}
	if !utf16LE {
		return bytes.TrimPrefix(output, []byte{0xef, 0xbb, 0xbf})
	}
	if output[0] == 0xff && output[1] == 0xfe {
		output = output[2:]
	}
	units := make([]uint16, 0, len(output)/2)
	for index := 0; index+1 < len(output); index += 2 {
		units = append(units, uint16(output[index])|uint16(output[index+1])<<8)
	}
	return []byte(string(utf16.Decode(units)))
}

func runPowerShellSecret(script string, environment []string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	wrapped := "$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$InformationPreference='SilentlyContinue';" + script
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", wrapped)
	cmd.Env = append(os.Environ(), environment...)
	// Keep stderr separate. Windows PowerShell may emit harmless CLIXML stream
	// records there even when the command succeeds; mixing those records into
	// stdout corrupts the JSON metadata returned by the BitLocker scripts.
	stdout := &cappedCommandOutput{}
	stderr := &cappedCommandOutput{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := runCommandInKillJob(cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("Windows encryption operation timed out")
	}
	if err != nil {
		// Never return PowerShell output from a secret-bearing operation: it
		// may contain the numerical recovery password.
		return nil, fmt.Errorf("Windows encryption operation failed")
	}
	return normalizePowerShellOutput(stdout.Bytes()), nil
}

func escrowBitLockerRecovery(jobID string, state bitLockerProtector) error {
	_, err := apiPostAuth("/api/agent/bitlocker-recovery", map[string]interface{}{
		"job_id": jobID, "volume_mount": state.MountPoint,
		"protector_id": state.ProtectorID, "recovery_password": state.RecoveryPassword,
		"volume_status": state.VolumeStatus, "protection_status": state.ProtectionStatus,
		"encryption_percentage": state.EncryptionPercent,
	})
	if err != nil {
		return fmt.Errorf("Warden recovery-key escrow failed; disk encryption was not started: %w", err)
	}
	return nil
}

func manageBitLocker(jobID string, rotate bool) (int, string, error) {
	if runtime.GOOS != "windows" {
		return 1, "", fmt.Errorf("BitLocker is only available on Windows")
	}
	recoveryPassword, err := generateBitLockerRecoveryPassword()
	if err != nil {
		return 1, "", err
	}
	raw, err := runPowerShellSecret(prepareBitLockerScript, []string{"WARDEN_RECOVERY_PASSWORD=" + recoveryPassword}, 90*time.Second)
	if err != nil {
		return 1, "", err
	}
	var state bitLockerProtector
	protectorPattern := `^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`
	if err := json.Unmarshal(bytes.TrimSpace(raw), &state); err != nil {
		_, _ = runPowerShellSecret(removeBitLockerRecoveryByPasswordScript, []string{"WARDEN_RECOVERY_PASSWORD=" + recoveryPassword}, 90*time.Second)
		return 1, "", fmt.Errorf("Windows created a recovery protector, but its metadata could not be read")
	}
	state.MountPoint = strings.TrimSpace(state.MountPoint)
	state.ProtectorID = strings.TrimSpace(state.ProtectorID)
	if state.MountPoint == "" || !regexp.MustCompile(protectorPattern).MatchString(state.ProtectorID) {
		_, _ = runPowerShellSecret(removeBitLockerRecoveryByPasswordScript, []string{"WARDEN_RECOVERY_PASSWORD=" + recoveryPassword}, 90*time.Second)
		return 1, "", fmt.Errorf("Windows created a recovery protector, but did not return a valid protector ID")
	}
	state.RecoveryPassword = recoveryPassword
	if err := escrowBitLockerRecovery(jobID, state); err != nil {
		_, _ = runPowerShellSecret(removeBitLockerRecoveryByPasswordScript, []string{"WARDEN_RECOVERY_PASSWORD=" + recoveryPassword}, 90*time.Second)
		return 1, "", err
	}

	if rotate || strings.EqualFold(state.VolumeStatus, "FullyDecrypted") {
		// The new key is safely escrowed before old recovery protectors are
		// removed. On an unencrypted volume this also cleans up a protector
		// left by an interrupted earlier enrollment. Failure leaves extra valid
		// protectors, never a locked disk.
		cleanup := `$ErrorActionPreference='Stop'; $v=Get-BitLockerVolume -MountPoint $env:SystemDrive; @($v.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword' -and [string]$_.KeyProtectorId -ne $env:WARDEN_KEEP_PROTECTOR}) | ForEach-Object { Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId -ErrorAction Stop }`
		if _, err := runPowerShellSecret(cleanup, []string{"WARDEN_KEEP_PROTECTOR=" + state.ProtectorID}, 90*time.Second); err != nil {
			return 1, "", fmt.Errorf("new recovery key was escrowed, but old protector cleanup failed")
		}
	}
	if rotate {
		return 0, "Rotated BitLocker recovery protector and securely escrowed the new key in Warden.", nil
	}

	// Escrow is complete. Only now may Windows start or resume encryption.
	enable := `$ErrorActionPreference='Stop'; $m=$env:SystemDrive; $v=Get-BitLockerVolume -MountPoint $m -ErrorAction Stop; if ([string]$v.VolumeStatus -eq 'FullyDecrypted') { $t=Get-Tpm -ErrorAction Stop; if (-not $t.TpmPresent -or -not $t.TpmReady) { throw 'A ready TPM is required; Warden will not create a clear-key protector' }; Enable-BitLocker -MountPoint $m -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest -ErrorAction Stop | Out-Null } elseif ([string]$v.ProtectionStatus -eq 'Off') { Resume-BitLocker -MountPoint $m -ErrorAction Stop | Out-Null }`
	if _, err := runPowerShellSecret(enable, nil, 2*time.Minute); err != nil {
		return 1, "", fmt.Errorf("recovery key is safely escrowed, but BitLocker could not be enabled: %w", err)
	}
	// Refresh the displayed volume state without exposing it through a job log.
	if refreshedRaw, refreshErr := runPowerShellSecret(readBitLockerStatusScript, nil, 90*time.Second); refreshErr == nil {
		var refreshed bitLockerProtector
		if json.Unmarshal(bytes.TrimSpace(refreshedRaw), &refreshed) == nil {
			refreshed.MountPoint, refreshed.ProtectorID, refreshed.RecoveryPassword = state.MountPoint, state.ProtectorID, state.RecoveryPassword
			_ = escrowBitLockerRecovery(jobID, refreshed)
		}
	}
	return 0, "BitLocker enabled with XTS-AES-256; recovery key securely escrowed in Warden.", nil
}
