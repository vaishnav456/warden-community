package main

import (
	"archive/zip"
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	diskPkg "github.com/shirou/gopsutil/v3/disk"
	memPkg "github.com/shirou/gopsutil/v3/mem"

	windowsPkg "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var operationWhitelist = map[string]bool{
	"INSTALL_APP":               true,
	"UNINSTALL_APP":             true,
	"CREATE_USER":               true,
	"PROVISION_WARDEN_IDENTITY": true,
	"WARDEN_ONLY_LOCKDOWN":      true,
	"DELETE_USER":               true,
	"RESET_PASSWORD":            true,
	"DISABLE_USER":              true,
	"ENABLE_USER":               true,
	"GRANT_ELEVATION":           true,
	"REVOKE_ELEVATION":          true,
	"RUN_CMD":                   true,
	"REBOOT":                    true,
	"SHUTDOWN":                  true,
	"COLLECT_SYSINFO":           true,
	"COLLECT_SOFTWARE":          true,
	"UPDATE_AGENT":              true,
	"SET_PERIPHERAL_POLICY":     true,
	"SETUP_REMOTE_ACCESS":       true,
	"REMOVE_REMOTE_ACCESS":      true,
	"COMPLIANCE_SCAN":           true,
	"FILE_PUSH":                 true,
	"FILE_PULL":                 true,
	"LIST_DIRECTORY":            true,
	"GET_EVENT_LOGS":            true,
	"WINDOWS_UPDATE":            true,
	"UNINSTALL_AGENT":           true,
	"REINSTALL_AGENT":           true,
	"PUSH_LOCAL_POLICY":         true,
	"CHECK_POLICY_DRIFT":        true,
	"COLLECT_USERS":             true,
	"ROTATE_TLS_PINS":           true,
	"CONFIGURE_DEVICE_IDENTITY": true,
	"CAPTURE_PACKETS":           true,
	"COLLECT_NETWORK_FLOWS":     true,
	"SYNC_WARDEN_HOME":          true,
	"APPLY_DEVICE_EXPERIENCE":   true,
	"ENABLE_BITLOCKER":          true,
	"ROTATE_BITLOCKER_RECOVERY": true,
}

const maxRemoteTransferBytes = 8 * 1024 * 1024
const maxCommandOutputBytes = 1024 * 1024

var packetCaptureMu sync.Mutex

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

type logFn func(line string)

func dispatchJob(env *Envelope, log logFn) (int, string, error) {
	if !operationWhitelist[env.Operation] {
		return 1, "", fmt.Errorf("operation '%s' is not allowed", env.Operation)
	}
	p := env.Payload
	switch env.Operation {
	case "INSTALL_APP":
		return installApp(env.JobID, p, log)
	case "UNINSTALL_APP":
		return uninstallApp(p)
	case "CREATE_USER":
		return createUser(p)
	case "PROVISION_WARDEN_IDENTITY":
		return provisionWardenIdentity(p)
	case "WARDEN_ONLY_LOCKDOWN":
		return applyWardenOnlyLockdown(p)
	case "DELETE_USER":
		return deleteUser(p)
	case "RESET_PASSWORD":
		return resetPassword(p)
	case "DISABLE_USER":
		return disableUser(p)
	case "ENABLE_USER":
		return enableUser(p)
	case "GRANT_ELEVATION":
		return grantElevation(p)
	case "REVOKE_ELEVATION":
		return revokeElevation(p)
	case "RUN_CMD":
		return runCmdJob(p)
	case "REBOOT":
		return reboot(p)
	case "SHUTDOWN":
		return shutdown(p)
	case "COLLECT_SYSINFO":
		return collectSysinfo()
	case "COLLECT_SOFTWARE":
		return collectSoftware()
	case "UPDATE_AGENT":
		return updateAgent(env.JobID, p, log)
	case "SET_PERIPHERAL_POLICY":
		return setPeripheralPolicy(p)
	case "SETUP_REMOTE_ACCESS":
		return setupRemoteAccess(env.JobID, p)
	case "REMOVE_REMOTE_ACCESS":
		return removeRemoteAccess()
	case "COMPLIANCE_SCAN":
		return complianceScan(env.JobID, p)
	case "FILE_PUSH":
		return filePush(p)
	case "FILE_PULL":
		return filePull(env.JobID, p)
	case "LIST_DIRECTORY":
		return listDirectory(p)
	case "GET_EVENT_LOGS":
		return getEventLogs(env.JobID, p)
	case "WINDOWS_UPDATE":
		return windowsUpdate(p)
	case "UNINSTALL_AGENT":
		return performSelfRemoval()
	case "REINSTALL_AGENT":
		return prepareAgentReinstall(env.JobID, p)
	case "PUSH_LOCAL_POLICY":
		return pushLocalPolicy(p)
	case "CHECK_POLICY_DRIFT":
		var keys []string
		if rawKeys, ok := p["keys"].([]interface{}); ok {
			for _, k := range rawKeys {
				if s, ok := k.(string); ok {
					keys = append(keys, s)
				}
			}
		}
		return checkPolicyDrift(keys)
	case "COLLECT_USERS":
		return collectUsers()
	case "ROTATE_TLS_PINS":
		return rotateTLSPins(p)
	case "CONFIGURE_DEVICE_IDENTITY":
		return configureDeviceIdentity(p)
	case "CAPTURE_PACKETS":
		return capturePackets(env.JobID, p, log)
	case "COLLECT_NETWORK_FLOWS":
		return collectNetworkFlows()
	case "SYNC_WARDEN_HOME":
		return syncWardenHomeJob(p)
	case "APPLY_DEVICE_EXPERIENCE":
		return applyDeviceExperience(p)
	case "ENABLE_BITLOCKER":
		return manageBitLocker(env.JobID, false)
	case "ROTATE_BITLOCKER_RECOVERY":
		return manageBitLocker(env.JobID, true)
	}
	return 1, "", fmt.Errorf("unhandled operation: %s", env.Operation)
}

// ── Managed device experience ────────────────────────────────────────────────

const maxExperienceImageBytes = 10 * 1024 * 1024

func experienceBrandingDir() string {
	base := strings.TrimSpace(os.Getenv("ProgramData"))
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Warden", "Branding")
}

func downloadExperienceAsset(assetID, label string) (string, error) {
	assetID = strings.ToLower(strings.TrimSpace(assetID))
	if matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, assetID); !matched {
		return "", fmt.Errorf("invalid %s asset identifier", label)
	}
	req, err := http.NewRequest(http.MethodGet, serverURL()+"/api/agent/branding/"+assetID, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Agent-Key", apiKey)
	clientMu.Lock()
	if httpClient == nil {
		clientMu.Unlock()
		return "", fmt.Errorf("secure HTTP client is unavailable")
	}
	client := *httpClient
	clientMu.Unlock()
	client.Timeout = 60 * time.Second
	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", label, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s returned HTTP %d", label, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxExperienceImageBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxExperienceImageBytes {
		return "", fmt.Errorf("%s image is empty or exceeds 10 MB", label)
	}
	extension := ""
	if bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		extension = ".png"
	} else if bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}) {
		extension = ".jpg"
	} else {
		return "", fmt.Errorf("%s is not a PNG or JPEG image", label)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != assetID {
		return "", fmt.Errorf("%s asset integrity check failed", label)
	}
	// The Agent service runs as SYSTEM, while the desktop refresh helper runs
	// inside the signed-in user's session. Keep branding outside the agent's
	// SYSTEM-only data directory and grant Users read/execute only; otherwise
	// Windows silently retains the previous wallpaper because the user cannot
	// read the file even though the service wrote the policy successfully.
	directory := experienceBrandingDir()
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	if out, err := exec.Command("icacls.exe", directory, "/inheritance:r", "/grant:r",
		`*S-1-5-18:(OI)(CI)(F)`, `*S-1-5-32-545:(OI)(CI)(RX)`).CombinedOutput(); err != nil {
		return "", fmt.Errorf("protect branding directory: %w: %s", err, strings.TrimSpace(string(out)))
	}
	path := filepath.Join(directory, label+extension)
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return path, nil
}

func applyPersonalizationImage(kind, path, fit string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	prefix := "DesktopImage"
	if kind == "lock_screen" {
		prefix = "LockScreenImage"
		policy, _, policyErr := registry.CreateKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Policies\Microsoft\Windows\Personalization`, registry.SET_VALUE)
		if policyErr != nil {
			return policyErr
		}
		if policyErr = policy.SetStringValue("LockScreenImage", path); policyErr != nil {
			policy.Close()
			return policyErr
		}
		policy.Close()
	}
	if err := key.SetStringValue(prefix+"Path", path); err != nil {
		return err
	}
	if err := key.SetStringValue(prefix+"Url", path); err != nil {
		return err
	}
	if err := key.SetDWordValue(prefix+"Status", 1); err != nil {
		return err
	}
	if kind == "desktop" {
		style, tile := "10", "0"
		switch fit {
		case "fit":
			style = "6"
		case "stretch":
			style = "2"
		case "center":
			style = "0"
		case "tile":
			style, tile = "0", "1"
		case "span":
			style = "22"
		}
		policy, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer policy.Close()
		if err := policy.SetStringValue("Wallpaper", path); err != nil {
			return err
		}
		if err := policy.SetStringValue("WallpaperStyle", style); err != nil {
			return err
		}
		if err := policy.SetStringValue("TileWallpaper", tile); err != nil {
			return err
		}
	}
	return nil
}

// applyInteractiveWallpaper runs as the active user, not as the service.
// HKLM policy makes the setting durable; HKCU + SPI_SETDESKWALLPAPER makes
// the already-running Explorer desktop adopt it immediately.
func applyInteractiveWallpaper(path, fit string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wallpaper path must be absolute")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("wallpaper is unreadable in user session: %w", err)
	}
	style, tile := "10", "0"
	switch fit {
	case "fit":
		style = "6"
	case "stretch":
		style = "2"
	case "center":
		style = "0"
	case "tile":
		style, tile = "0", "1"
	case "span":
		style = "22"
	case "fill":
	default:
		return fmt.Errorf("invalid wallpaper fit")
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	if err = key.SetStringValue("WallpaperStyle", style); err == nil {
		err = key.SetStringValue("TileWallpaper", tile)
	}
	key.Close()
	if err != nil {
		return err
	}
	pathPtr, err := windowsPkg.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	proc := windowsPkg.NewLazySystemDLL("user32.dll").NewProc("SystemParametersInfoW")
	result, _, callErr := proc.Call(20, 0, uintptr(unsafe.Pointer(pathPtr)), 0x01|0x02)
	if result == 0 {
		return fmt.Errorf("Windows rejected live wallpaper refresh: %v", callErr)
	}
	return nil
}

func applyDeviceExperience(p map[string]interface{}) (int, string, error) {
	fit, _ := p["image_fit"].(string)
	if fit == "" {
		fit = "fill"
	}
	if !map[string]bool{"fill": true, "fit": true, "stretch": true, "center": true, "tile": true, "span": true}[fit] {
		return 1, "", fmt.Errorf("invalid image fit")
	}
	applied := []string{}
	if asset, _ := p["wallpaper_asset_id"].(string); asset != "" {
		path, err := downloadExperienceAsset(asset, "desktop-wallpaper")
		if err != nil {
			return 1, "", err
		}
		if err := applyPersonalizationImage("desktop", path, fit); err != nil {
			return 1, "", err
		}
		exePath, err := os.Executable()
		if err != nil {
			return 1, "", err
		}
		helper, err := launchInteractiveHelper(exePath, []string{"--apply-user-wallpaper", path, fit})
		if errors.Is(err, syscall.Errno(1008)) { // ERROR_NO_TOKEN: sign-in screen, no interactive user yet.
			applied = append(applied, "desktop wallpaper (staged for next sign-in)")
		} else if err != nil {
			return 1, "", fmt.Errorf("refresh signed-in user's wallpaper: %w", err)
		} else if code, finished := helper.wait(20 * time.Second); !finished {
			helper.terminate(2 * time.Second)
			return 1, "", fmt.Errorf("wallpaper refresh helper timed out")
		} else if code != 0 {
			return int(code), "", fmt.Errorf("Windows did not accept the wallpaper in the active user session")
		} else {
			applied = append(applied, "desktop wallpaper")
		}
	}
	if asset, _ := p["lock_screen_asset_id"].(string); asset != "" {
		path, err := downloadExperienceAsset(asset, "lock-screen")
		if err != nil {
			return 1, "", err
		}
		if err := applyPersonalizationImage("lock_screen", path, fit); err != nil {
			return 1, "", err
		}
		applied = append(applied, "lock screen")
	}
	announcement, _ := p["announcement_message"].(string)
	if announcement != "" {
		title, _ := p["announcement_title"].(string)
		severity, _ := p["announcement_severity"].(string)
		requireAck, _ := p["announcement_require_ack"].(bool)
		if title == "" || len(title) > 120 || len(announcement) > 2000 || !map[string]bool{"info": true, "warning": true, "critical": true}[severity] {
			return 1, "", fmt.Errorf("invalid announcement")
		}
		exePath, err := os.Executable()
		if err != nil {
			return 1, "", err
		}
		helper, err := launchInteractiveHelper(exePath, []string{"--user-announcement", title, announcement, severity})
		if err != nil {
			return 1, "", fmt.Errorf("display announcement: %w", err)
		}
		if requireAck {
			if _, finished := helper.wait(5 * time.Minute); !finished {
				helper.terminate(2 * time.Second)
				return 1, "", fmt.Errorf("announcement acknowledgement timed out")
			}
		} else {
			go func() { time.Sleep(5 * time.Minute); helper.terminate(2 * time.Second) }()
		}
		applied = append(applied, "user announcement")
	}
	if len(applied) == 0 {
		return 1, "", fmt.Errorf("no device experience changes supplied")
	}
	return 0, "Applied " + strings.Join(applied, ", "), nil
}

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

// ── App install/uninstall ──────────────────────────────────────────────────────

func installApp(jobID string, p map[string]interface{}, log logFn) (int, string, error) {
	appURL, _ := p["app_url"].(string)
	sha256hex, _ := p["sha256"].(string)
	installArgs, _ := p["install_args"].(string)
	runAs, _ := p["run_as"].(string)
	if appURL == "" {
		return 1, "", fmt.Errorf("missing app_url")
	}
	// appURL is always the server's /api/agent/apps/<id>/download route,
	// which never itself carries a file extension (only the stored file on
	// the server side does) — deriving it by splitting appURL on "." used
	// to grab the domain's TLD instead (e.g. "com/api/agent/apps/42/download"
	// from warden.example.com/...), producing a garbage nested path that
	// downloadFile could never write to. The server now sends the real
	// extension explicitly via payload.ext (see warden.js's deployApp());
	// falling back to .exe only for any already-queued job predating that.
	extRaw, _ := p["ext"].(string)
	ext := strings.ToLower(strings.TrimPrefix(extRaw, "."))
	if ext == "" {
		ext = "exe"
	}
	if ext != "exe" && ext != "msi" {
		return 1, "", fmt.Errorf("unsupported installer format: %s", ext)
	}
	stageDir, err := jobStageDir(jobID)
	if err != nil {
		return 1, "", err
	}
	if err := createSystemOnlyDirectory(stageDir); err != nil {
		return 1, "", fmt.Errorf("secure installer staging directory: %w", err)
	}
	if runAs != "" {
		if err := grantDirectoryRead(stageDir, runAs); err != nil {
			return 1, "", fmt.Errorf("grant installer read access to requested user: %w", err)
		}
	}
	defer os.RemoveAll(stageDir)

	dest := filepath.Join(stageDir, "installer."+ext)
	if err := downloadFile(appURL, dest, sha256hex); err != nil {
		return 1, "", fmt.Errorf("download failed: %w", err)
	}
	requireSignature, _ := p["require_authenticode"].(bool)
	requireSignature = requireSignature || requireAuthenticodeUpdates()
	return runInstaller(dest, sha256hex, requireSignature, installArgs, runAs, log)
}

// downloadFile fetches url through the same TLS-pinned, authenticated
// client used for every other agent-server call (see comms.go's
// buildPinningClient/apiPostRaw) — not a bare http.Get(). This matters more
// here than almost anywhere else in the agent: the downloaded bytes get
// executed, either directly (INSTALL_APP) or by replacing the running
// privileged service binary (UPDATE_AGENT). sha256 verification alone
// doesn't stop a MITM that also controls what bytes are served over an
// unpinned connection — pinning is what actually closes that gap.
func downloadFile(rawURL, dest, sha256hex string) error {
	sha256hex = strings.ToLower(strings.TrimSpace(sha256hex))
	if len(sha256hex) != 64 {
		return fmt.Errorf("a valid SHA-256 digest is required")
	}
	if _, err := hex.DecodeString(sha256hex); err != nil {
		return fmt.Errorf("invalid SHA-256 digest: %w", err)
	}

	validatedURL, err := validatePinnedDownloadURL(rawURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("GET", validatedURL, nil)
	if err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}
	req.Header.Set("X-Agent-Key", apiKey)

	clientMu.Lock()
	client := httpClient
	clientMu.Unlock()
	if client == nil {
		return fmt.Errorf("comms not initialized — call initComms first")
	}
	client2 := *client
	client2.Timeout = 5 * time.Minute
	client2.CheckRedirect = rejectRedirect
	resp, err := client2.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("download redirect refused (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}

	// Stream installers to disk instead of buffering as much as 500 MiB in
	// the long-running service process. The old allocation could push a busy
	// endpoint into the OOM killer/page-file death spiral.
	const maxDownloadBytes int64 = 500 * 1024 * 1024
	tmp := dest + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	keepTemp := false
	defer func() {
		_ = out.Close()
		if !keepTemp {
			_ = os.Remove(tmp)
		}
	}()
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return err
	}
	if written > maxDownloadBytes {
		return fmt.Errorf("download exceeds 500 MiB limit")
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != sha256hex {
		return fmt.Errorf("SHA-256 mismatch: expected %s got %s", sha256hex, got)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	keepTemp = true
	return nil
}

func validatePinnedDownloadURL(rawURL string) (string, error) {
	candidate, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid download URL: %w", err)
	}
	base, err := url.Parse(serverURL())
	if err != nil {
		return "", fmt.Errorf("invalid configured server URL: %w", err)
	}
	if !strings.EqualFold(candidate.Scheme, "https") || candidate.Host == "" || candidate.User != nil {
		return "", fmt.Errorf("download URL must be an HTTPS URL without user credentials")
	}
	if !strings.EqualFold(candidate.Host, base.Host) {
		return "", fmt.Errorf("download URL origin does not match the configured Warden server")
	}
	if candidate.Fragment != "" {
		return "", fmt.Errorf("download URL fragments are not allowed")
	}
	return candidate.String(), nil
}

func verifyFileSHA256(path, expected string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if len(expected) != 64 {
		return fmt.Errorf("a valid SHA-256 digest is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("SHA-256 mismatch immediately before execution: expected %s got %s", expected, actual)
	}
	return nil
}

func verifyExecutionArtifact(path, expectedSHA256 string, requireSignature bool) error {
	if err := verifyFileSHA256(path, expectedSHA256); err != nil {
		return err
	}
	if requireSignature {
		if err := verifyAuthenticode(path); err != nil {
			return fmt.Errorf("Authenticode verification failed: %w", err)
		}
	}
	return nil
}

func runInstaller(dest, expectedSHA256 string, requireSignature bool, installArgs, runAs string, _ logFn) (int, string, error) {
	if err := verifyExecutionArtifact(dest, expectedSHA256, requireSignature); err != nil {
		return 1, "", fmt.Errorf("installer integrity verification failed: %w", err)
	}
	ext := strings.ToLower(filepath.Ext(dest))
	var cmd *exec.Cmd
	switch ext {
	case ".msi":
		args := []string{"/i", dest, "/quiet", "/norestart"}
		if installArgs != "" {
			args = append(args, strings.Fields(installArgs)...)
		}
		cmd = exec.Command("msiexec", args...)
	case ".exe":
		args := []string{dest}
		if installArgs != "" {
			args = append(args, strings.Fields(installArgs)...)
		}
		cmd = exec.Command(args[0], args[1:]...)
	default:
		return 1, "", fmt.Errorf("unsupported installer format: %s", ext)
	}
	if runAs != "" {
		return runCommandAsUser(
			runAs, cmd.Path, cmd.Args[1:], jobTimeoutSec*time.Second,
		)
	}
	ctx, cancel := context.WithTimeout(context.Background(), jobTimeoutSec*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	out, err := boundedCombinedOutput(cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return 1, string(out), fmt.Errorf("installer timed out after %d seconds", jobTimeoutSec)
	}
	if err != nil {
		return 1, string(out), fmt.Errorf("installer failed: %w", err)
	}
	return 0, string(out), nil
}

func uninstallApp(p map[string]interface{}) (int, string, error) {
	productName, _ := p["product_name"].(string)
	if productName == "" {
		return 1, "", fmt.Errorf("missing product_name")
	}
	uninstallStr, err := findUninstallString(productName)
	if err != nil {
		return 1, "", err
	}
	fields, err := windowsPkg.DecomposeCommandLine(uninstallStr)
	if err != nil {
		return 1, "", fmt.Errorf("parse UninstallString: %w", err)
	}
	if len(fields) == 0 {
		return 1, "", fmt.Errorf("empty UninstallString")
	}
	executable := os.ExpandEnv(fields[0])
	isMSIExec := strings.EqualFold(executable, "msiexec") ||
		strings.EqualFold(executable, "msiexec.exe")
	if !isMSIExec {
		executable, err = resolveAllowedPath(executable, []string{
			`c:\windows\`,
			`c:\program files\`,
			`c:\program files (x86)\`,
		})
		if err != nil {
			return 1, "", fmt.Errorf("uninstall executable outside allowed locations: %w", err)
		}
	}
	args := fields[1:]
	if isMSIExec {
		hasQuiet := false
		for _, a := range args {
			if strings.EqualFold(a, "/quiet") {
				hasQuiet = true
				break
			}
		}
		if !hasQuiet {
			args = append(args, "/quiet", "/norestart")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), jobTimeoutSec*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	out, err := boundedCombinedOutput(cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return 1, string(out), fmt.Errorf("uninstall timed out after %d seconds", jobTimeoutSec)
	}
	if err != nil {
		return 1, string(out), fmt.Errorf("uninstall failed: %w", err)
	}
	return 0, string(out), nil
}

func findUninstallString(productName string) (string, error) {
	regPaths := []struct {
		hive registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	for _, rp := range regPaths {
		k, err := registry.OpenKey(rp.hive, rp.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subkeys, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sub := range subkeys {
			sk, err := registry.OpenKey(rp.hive, rp.path+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			if strings.EqualFold(name, productName) {
				unstr, _, _ := sk.GetStringValue("UninstallString")
				sk.Close()
				if unstr != "" {
					return unstr, nil
				}
			}
			sk.Close()
		}
	}
	return "", fmt.Errorf("product '%s' not found in registry", productName)
}

// ── User management ───────────────────────────────────────────────────────────

func createUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	password, _ := p["password"].(string)
	fullName, _ := p["full_name"].(string)
	profilePhoto, _ := p["profile_photo"].(string)
	isAdmin, _ := p["is_admin"].(bool)
	mustChange, _ := p["must_change_password"].(bool)
	purpose, _ := p["purpose"].(string)
	if username == "" || password == "" {
		return 1, "", fmt.Errorf("username and password are required")
	}
	if err := createLocalUserSecure(username, password, fullName, mustChange); err != nil {
		// A recovery account deliberately survives uninstall/re-enrollment.
		// Reconcile only an explicitly marked recovery job; never take over an
		// arbitrary pre-existing local account from a normal CREATE_USER job.
		if purpose != "warden_recovery" || !errors.Is(err, syscall.Errno(2224)) {
			return 1, "", fmt.Errorf("create local user: %w", err)
		}
		if err := setLocalUserPasswordSecure(username, password); err != nil {
			return 1, "", fmt.Errorf("rotate recovery account password: %w", err)
		}
		if fullName != "" {
			if err := setLocalUserFullNameSecure(username, fullName); err != nil {
				return 1, "", fmt.Errorf("update recovery account name: %w", err)
			}
		}
	}
	if isAdmin {
		if groupErr := ensureLocalGroupMemberSecure("Administrators", username); groupErr != nil {
			// Administrator membership is part of the requested account state.
			// Do not report success with a silently under-privileged account.
			if purpose != "warden_recovery" {
				_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			}
			return 1, "", fmt.Errorf("grant administrator rights: %w", groupErr)
		}
	}
	if profilePhoto != "" {
		if err := applyUserProfilePicture(username, profilePhoto); err != nil {
			// A requested portrait is part of the desired account state. Avoid
			// reporting a half-provisioned user when Windows rejects the image.
			_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			return 1, "", fmt.Errorf("set profile photo: %w", err)
		}
	}
	return 0, fmt.Sprintf("Local account %s provisioned securely", username), nil
}

func decodeSECEditConfig(data []byte) string {
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		words := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			words = append(words, binary.LittleEndian.Uint16(data[i:i+2]))
		}
		return string(utf16.Decode(words))
	}
	return string(data)
}

func encodeSECEditConfig(text string) []byte {
	words := utf16.Encode([]rune(text))
	data := make([]byte, 2+len(words)*2)
	data[0], data[1] = 0xff, 0xfe
	for i, word := range words {
		binary.LittleEndian.PutUint16(data[2+i*2:], word)
	}
	return data
}

func addDeniedNetworkLogonSID(configText, sid string) (string, error) {
	if !regexp.MustCompile(`^S-1-(?:\d+-){1,14}\d+$`).MatchString(sid) {
		return "", fmt.Errorf("invalid Windows SID")
	}
	lines := strings.Split(strings.ReplaceAll(configText, "\r\n", "\n"), "\n")
	sectionIndex := -1
	insertIndex := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(trimmed, "[Privilege Rights]") {
			sectionIndex, insertIndex = i, i+1
			continue
		}
		if sectionIndex >= 0 && i > sectionIndex && strings.HasPrefix(trimmed, "[") {
			if insertIndex < 0 {
				insertIndex = i
			}
			break
		}
		if sectionIndex >= 0 && strings.HasPrefix(strings.ToLower(trimmed), "sedenynetworklogonright") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				return "", fmt.Errorf("malformed SeDenyNetworkLogonRight")
			}
			wanted := "*" + sid
			for _, existing := range strings.Split(parts[1], ",") {
				if strings.EqualFold(strings.TrimSpace(existing), wanted) {
					return strings.Join(lines, "\r\n"), nil
				}
			}
			value := strings.TrimSpace(parts[1])
			if value != "" {
				value += ","
			}
			lines[i] = "SeDenyNetworkLogonRight = " + value + wanted
			return strings.Join(lines, "\r\n"), nil
		}
		if sectionIndex >= 0 {
			insertIndex = i + 1
		}
	}
	if sectionIndex < 0 {
		return "", fmt.Errorf("secedit export omitted Privilege Rights")
	}
	line := "SeDenyNetworkLogonRight = *" + sid
	lines = append(lines[:insertIndex], append([]string{line}, lines[insertIndex:]...)...)
	return strings.Join(lines, "\r\n"), nil
}

func denyNetworkLogon(username string) error {
	sid, _, err := lookupWindowsAccountIdentity(username)
	if err != nil {
		return fmt.Errorf("resolve managed identity SID: %w", err)
	}
	dir, err := os.MkdirTemp("", "warden-user-rights-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "rights.inf")
	dbPath := filepath.Join(dir, "rights.sdb")
	if out, err := exec.Command("secedit", "/export", "/cfg", cfgPath, "/areas", "USER_RIGHTS", "/quiet").CombinedOutput(); err != nil {
		return fmt.Errorf("export user rights: %w: %s", err, string(out))
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	updated, err := addDeniedNetworkLogonSID(decodeSECEditConfig(raw), sid)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, encodeSECEditConfig(updated), 0600); err != nil {
		return err
	}
	if out, err := exec.Command("secedit", "/configure", "/db", dbPath, "/cfg", cfgPath,
		"/areas", "USER_RIGHTS", "/overwrite", "/quiet").CombinedOutput(); err != nil {
		return fmt.Errorf("apply user rights: %w: %s", err, string(out))
	}
	return nil
}

func managedIdentityProvisionAllowed(accountExists, secretExists, recoverExisting bool) bool {
	return !accountExists || secretExists || recoverExisting
}

func provisionWardenIdentity(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	credentialMode, _ := p["credential_mode"].(string)
	if credentialMode != "managed_shadow_v1" {
		// Backward compatibility for already-queued pre-provider jobs. New
		// servers never put the reusable Warden password in endpoint jobs.
		code, output, err := createUser(p)
		if err != nil {
			return code, output, err
		}
		if err := denyNetworkLogon(username); err != nil {
			_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			return 1, output, fmt.Errorf("secure Warden identity: %w", err)
		}
		return 0, fmt.Sprintf("Warden identity %s provisioned; network logon denied", username), nil
	}

	if !identityUsernamePattern.MatchString(username) {
		return 1, "", fmt.Errorf("invalid managed identity username")
	}
	fullName, _ := p["full_name"].(string)
	profilePhoto, _ := p["profile_photo"].(string)
	isAdmin, _ := p["is_admin"].(bool)
	recoverExisting, _ := p["recover_existing"].(bool)

	_, accountErr := exec.Command("net", "user", username).CombinedOutput()
	accountExists := accountErr == nil
	password, secretExists, err := managedIdentityPassword(username)
	if err != nil {
		return 1, "", err
	}
	if !managedIdentityProvisionAllowed(accountExists, secretExists, recoverExisting) {
		return 1, "", fmt.Errorf("refusing to take over an unmanaged local account")
	}
	createdSecret := false
	if !secretExists {
		password, err = newManagedIdentityPassword()
		if err != nil {
			return 1, "", fmt.Errorf("generate device credential: %w", err)
		}
		if err := putManagedIdentityPassword(username, password); err != nil {
			return 1, "", err
		}
		createdSecret = true
	}

	if !accountExists {
		if createErr := createLocalUserSecure(username, password, fullName, false); createErr != nil {
			if createdSecret {
				_ = removeManagedIdentityPassword(username)
			}
			return 1, "", fmt.Errorf("create managed shadow account: %w", createErr)
		}
		accountExists = true
	} else {
		if resetErr := setLocalUserPasswordSecure(username, password); resetErr != nil {
			return 1, "", fmt.Errorf("repair managed shadow credential: %w", resetErr)
		}
	}
	if out, enableErr := exec.Command("net", "user", username, "/active:yes").CombinedOutput(); enableErr != nil {
		return 1, string(out), fmt.Errorf("enable managed shadow account: %w", enableErr)
	}
	groupAction := "/delete"
	if isAdmin {
		groupAction = "/add"
	}
	// Removing a standard user that is not a member returns an error; only an
	// add failure is fatal because it would violate assigned privilege state.
	if out, groupErr := exec.Command("net", "localgroup", "Administrators", username, groupAction).CombinedOutput(); groupErr != nil && isAdmin {
		return 1, string(out), fmt.Errorf("grant managed administrator rights: %w", groupErr)
	}
	if profilePhoto != "" {
		if err := applyUserProfilePicture(username, profilePhoto); err != nil {
			return 1, "", fmt.Errorf("set managed identity profile photo: %w", err)
		}
	}
	if err := denyNetworkLogon(username); err != nil {
		if createdSecret {
			_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			_ = removeManagedIdentityPassword(username)
		}
		return 1, "", fmt.Errorf("secure Warden identity: %w", err)
	}
	return 0, fmt.Sprintf("Warden identity %s provisioned with a machine-bound shadow credential", username), nil
}

func deleteUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	sid, _, sidErr := lookupWindowsAccountIdentity(username)
	out, err := exec.Command("net", "user", username, "/delete").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("net user delete: %w", err)
	}
	if sidErr == nil {
		if err := removeUserProfilePicture(sid); err != nil {
			return 1, string(out), fmt.Errorf("user deleted but profile-photo cleanup failed: %w", err)
		}
	}
	if err := removeManagedIdentityPassword(username); err != nil {
		return 1, string(out), fmt.Errorf("user deleted but managed credential cleanup failed: %w", err)
	}
	return 0, fmt.Sprintf("User %s deleted", username), nil
}

func resetPassword(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	newPw, _ := p["new_password"].(string)
	if username == "" || newPw == "" {
		return 1, "", fmt.Errorf("username and new_password required")
	}
	if _, managed, err := managedIdentityPassword(username); err != nil {
		return 1, "", fmt.Errorf("check managed identity ownership: %w", err)
	} else if managed {
		return 1, "", fmt.Errorf("managed Warden identity passwords must be changed from Central Directory")
	}
	if err := setLocalUserPasswordSecure(username, newPw); err != nil {
		return 1, "", fmt.Errorf("set local user password: %w", err)
	}
	return 0, fmt.Sprintf("Password reset for %s", username), nil
}

func disableUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	out, err := exec.Command("net", "user", username, "/active:no").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("disable user: %w", err)
	}
	return 0, fmt.Sprintf("User %s disabled", username), nil
}

func enableUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	out, err := exec.Command("net", "user", username, "/active:yes").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("enable user: %w", err)
	}
	return 0, fmt.Sprintf("User %s enabled", username), nil
}

// applyWardenOnlyLockdown converts an enrolled workstation to Warden-managed
// interactive access.  It deliberately runs only after the server has seen a
// successful PROVISION_WARDEN_IDENTITY result.  The approved identity and a
// separate recovery administrator are made usable before any existing account
// is disabled, preventing a partial failure from locking everybody out.
func applyWardenOnlyLockdown(p map[string]interface{}) (int, string, error) {
	recoveryUsername, _ := p["recovery_admin_username"].(string)
	recoveryPassword, _ := p["recovery_admin_password"].(string)
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`).MatchString(recoveryUsername) || recoveryPassword == "" {
		return 1, "", fmt.Errorf("valid recovery administrator credentials are required")
	}
	allowed := map[string]bool{strings.ToLower(recoveryUsername): true}
	if raw, ok := p["allowed_users"].([]interface{}); ok {
		for _, value := range raw {
			username, ok := value.(string)
			if ok && regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`).MatchString(username) {
				allowed[strings.ToLower(username)] = true
			}
		}
	}
	if len(allowed) < 2 {
		return 1, "", fmt.Errorf("at least one Warden identity is required before lockdown")
	}

	// Confirm every approved Warden user exists and is enabled first.
	for username := range allowed {
		if strings.EqualFold(username, recoveryUsername) {
			continue
		}
		if out, err := exec.Command("net", "user", username).CombinedOutput(); err != nil {
			return 1, string(out), fmt.Errorf("approved Warden identity %s is not usable", username)
		}
		if out, err := exec.Command("net", "user", username, "/active:yes").CombinedOutput(); err != nil {
			return 1, string(out), fmt.Errorf("enable approved Warden identity %s: %w", username, err)
		}
	}

	// Create or rotate the independently controlled break-glass administrator.
	if _, err := exec.Command("net", "user", recoveryUsername).CombinedOutput(); err != nil {
		if createErr := createLocalUserSecure(recoveryUsername, recoveryPassword, "Warden Recovery Administrator", false); createErr != nil {
			return 1, "", fmt.Errorf("create recovery administrator: %w", createErr)
		}
	} else if resetErr := setLocalUserPasswordSecure(recoveryUsername, recoveryPassword); resetErr != nil {
		return 1, "", fmt.Errorf("rotate recovery administrator password: %w", resetErr)
	}
	if out, err := exec.Command("net", "user", recoveryUsername, "/active:yes").CombinedOutput(); err != nil {
		return 1, string(out), fmt.Errorf("enable recovery administrator: %w", err)
	}
	if out, err := exec.Command("net", "localgroup", "Administrators", recoveryUsername, "/add").CombinedOutput(); err != nil && !strings.Contains(strings.ToLower(string(out)), "already a member") {
		return 1, string(out), fmt.Errorf("grant recovery administrator rights: %w", err)
	}

	type localUser struct {
		Name    string `json:"Name"`
		SID     string `json:"SID"`
		Enabled bool   `json:"Enabled"`
	}
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-LocalUser | Select-Object Name,@{N='SID';E={$_.SID.Value}},Enabled | ConvertTo-Json -Compress`).CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("enumerate local users: %w", err)
	}
	raw := bytes.TrimSpace(out)
	if len(raw) > 0 && raw[0] == '{' {
		raw = append(append([]byte{'['}, raw...), ']')
	}
	var users []localUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return 1, string(out), fmt.Errorf("decode local users: %w", err)
	}
	disabled := []string{}
	for _, user := range users {
		nameFolded := strings.ToLower(user.Name)
		// Guest, DefaultAccount, and WDAGUtilityAccount are Windows-managed
		// identities. They are normally disabled already and are never made
		// usable by this workflow.
		systemManaged := strings.HasSuffix(user.SID, "-501") || strings.HasSuffix(user.SID, "-503") || strings.HasSuffix(user.SID, "-504")
		if allowed[nameFolded] || systemManaged || !user.Enabled {
			continue
		}
		if disableOut, disableErr := exec.Command("net", "user", user.Name, "/active:no").CombinedOutput(); disableErr != nil {
			return 1, string(disableOut), fmt.Errorf("disable unmanaged local user %s: %w", user.Name, disableErr)
		}
		disabled = append(disabled, user.Name)
	}

	restartOut, restartErr := exec.Command("shutdown", "/r", "/t", "30", "/d", "p:4:1", "/c", "Warden-only enrollment completed").CombinedOutput()
	if restartErr != nil {
		return 1, string(restartOut), fmt.Errorf("schedule post-enrollment restart: %w", restartErr)
	}
	return 0, fmt.Sprintf("Warden-only mode enabled; disabled %d unmanaged account(s): %s; restart scheduled in 30 seconds", len(disabled), strings.Join(disabled, ", ")), nil
}

// configureDeviceIdentity applies the zero-touch enrollment profile after the
// agent has authenticated. A DNS suffix is a Warden-managed machine identity
// and does not pretend to join an Active Directory domain.
func configureDeviceIdentity(p map[string]interface{}) (int, string, error) {
	targetHostname, _ := p["hostname"].(string)
	targetHostname = strings.ToUpper(strings.TrimSpace(targetHostname))
	domainSuffix, _ := p["domain_suffix"].(string)
	domainSuffix = strings.ToLower(strings.Trim(strings.TrimSpace(domainSuffix), "."))
	if targetHostname != "" && !regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{0,13}[A-Z0-9]$|^[A-Z0-9]$`).MatchString(targetHostname) {
		return 1, "", fmt.Errorf("managed hostname must be 1-15 letters, numbers or hyphens")
	}
	if domainSuffix != "" && (len(domainSuffix) > 253 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`).MatchString(domainSuffix)) {
		return 1, "", fmt.Errorf("invalid managed DNS suffix")
	}
	if targetHostname == "" && domainSuffix == "" {
		return 0, "No managed device identity requested", nil
	}

	currentHostname, _ := os.Hostname()
	hostnameChanged := targetHostname != "" && !strings.EqualFold(currentHostname, targetHostname)
	domainChanged := domainSuffix != "" && !strings.EqualFold(currentManagedDNSSuffix(), domainSuffix)
	if !hostnameChanged && !domainChanged {
		return 0, "Managed device identity already applied", nil
	}

	if hostnameChanged {
		script := fmt.Sprintf("Rename-Computer -NewName '%s' -Force -ErrorAction Stop", targetHostname)
		if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
			return 1, string(out), fmt.Errorf("rename computer: %w", err)
		}
	}
	if domainChanged {
		key, _, err := registry.CreateKey(
			registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
			registry.QUERY_VALUE|registry.SET_VALUE,
		)
		if err != nil {
			return 1, "", fmt.Errorf("open DNS identity registry: %w", err)
		}
		defer key.Close()
		if err := key.SetStringValue("NV Domain", domainSuffix); err != nil {
			return 1, "", fmt.Errorf("persist managed DNS suffix: %w", err)
		}
		if err := key.SetStringValue("Domain", domainSuffix); err != nil {
			return 1, "", fmt.Errorf("activate managed DNS suffix: %w", err)
		}
	}

	if out, err := exec.Command("shutdown.exe", "/r", "/t", "15", "/d", "p:4:1", "/c", "Warden device identity configured").CombinedOutput(); err != nil {
		return 1, string(out), fmt.Errorf("schedule device identity restart: %w", err)
	}
	return 0, fmt.Sprintf("Managed identity applied (hostname=%s, dns_suffix=%s); restart scheduled", targetHostname, domainSuffix), nil
}

func currentManagedDNSSuffix() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	if value, _, err := key.GetStringValue("Domain"); err == nil && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	value, _, _ := key.GetStringValue("NV Domain")
	return strings.TrimSpace(value)
}

// ── Local user discovery ──────────────────────────────────────────────────
//
// The server has had a /api/agent/users route (routes/agent_api.py's
// report_users()) since the Users tab UI was built, but earlier agent
// implementations never called
// it — CREATE_USER/DELETE_USER/etc. only ever acted on one named account,
// nothing ever reported the actual full list back, so the Users tab has
// never shown real data regardless of what's actually on the machine.

var netUserFieldRe = regexp.MustCompile(`^(.+?)\s{2,}(.+)$`)

// netUserField extracts a labeled field's value from "net user <name>"'s
// detail output, e.g. netUserField(out, "Account active") -> "Yes".
func netUserField(output, label string) string {
	for _, line := range strings.Split(output, "\n") {
		m := netUserFieldRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m != nil && strings.TrimSpace(m[1]) == label {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

// parseNetUserList parses bare "net user"'s columnar username listing
// (several names per line, between a dashed rule and the trailing
// "The command completed successfully." line).
func parseNetUserList(output string) []string {
	var names []string
	inList := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "----"):
			inList = true
		case strings.HasPrefix(line, "The command completed"):
			return names
		case inList && strings.TrimSpace(line) != "":
			names = append(names, strings.Fields(line)...)
		}
	}
	return names
}

// parseNetLocalGroupMembers parses "net localgroup <group>"'s one-name-
// per-line member listing the same way.
func parseNetLocalGroupMembers(output string) map[string]bool {
	members := map[string]bool{}
	inList := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "----"):
			inList = true
		case strings.HasPrefix(line, "The command completed"):
			return members
		case inList:
			if name := strings.TrimSpace(line); name != "" {
				members[name] = true
			}
		}
	}
	return members
}

func classifyWindowsAccount(domain, hostname string) string {
	switch {
	case strings.EqualFold(domain, "AzureAD"):
		return "entra"
	case strings.EqualFold(domain, "MicrosoftAccount"):
		return "microsoft"
	case domain == "" || strings.EqualFold(domain, hostname):
		return "local"
	default:
		return "domain"
	}
}

func collectUsers() (int, string, error) {
	// "net user" (bare) is known to exit non-zero for reasons unrelated to
	// the account listing itself -- e.g. it also tries to resolve the
	// local computer's own NetBIOS name for the "User accounts for \\..."
	// header, and a failure there still prints a completely valid account
	// list followed by "The command completed with one or more errors."
	// and exit code 1. Confirmed live: a real run returned exit 1 with a
	// perfectly parseable list of 5 real accounts. Parse the output
	// regardless of exit code, and only treat this as a real failure if
	// parsing actually yields nothing usable.
	out, cmdErr := exec.Command("net", "user").CombinedOutput()
	usernames := parseNetUserList(string(out))
	if len(usernames) == 0 {
		if cmdErr != nil {
			return 1, string(out), fmt.Errorf("net user: %w", cmdErr)
		}
		return 1, string(out), fmt.Errorf("net user: no accounts parsed from output")
	}

	adminOut, _ := exec.Command("net", "localgroup", "Administrators").CombinedOutput()
	admins := parseNetLocalGroupMembers(string(adminOut))
	adminsFolded := make(map[string]bool, len(admins))
	for name := range admins {
		adminsFolded[strings.ToLower(name)] = true
	}

	type reportedUser struct {
		Username      string `json:"username"`
		DisplayName   string `json:"display_name"`
		SID           string `json:"sid"`
		PrincipalName string `json:"principal_name"`
		AccountType   string `json:"account_type"`
		DomainName    string `json:"domain_name"`
		IsAdmin       bool   `json:"is_admin"`
		IsEnabled     bool   `json:"is_enabled"`
	}
	hostname, _ := os.Hostname()
	var users []reportedUser
	for _, uname := range usernames {
		detailOut, err := exec.Command("net", "user", uname).CombinedOutput()
		if err != nil {
			continue // account may have been deleted between listing and detail lookup
		}
		detail := string(detailOut)
		sid, domain, identityErr := lookupWindowsAccountIdentity(uname)
		if identityErr != nil {
			logWarn("User inventory: could not resolve identity for %s: %v", uname, identityErr)
		}
		principal := uname
		if domain != "" {
			principal = domain + `\` + uname
		}
		users = append(users, reportedUser{
			Username:      uname,
			DisplayName:   netUserField(detail, "Full Name"),
			SID:           sid,
			PrincipalName: principal,
			AccountType:   classifyWindowsAccount(domain, hostname),
			DomainName:    domain,
			IsAdmin:       adminsFolded[strings.ToLower(uname)],
			IsEnabled:     netUserField(detail, "Account active") == "Yes",
		})
	}

	if _, err := apiPostAuth("/api/agent/users", map[string]interface{}{"users": users}); err != nil {
		return 1, "", fmt.Errorf("report users: %w", err)
	}
	return 0, fmt.Sprintf("Reported %d local users", len(users)), nil
}

func grantElevation(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	duration := int64(60)
	if d, ok := p["duration_minutes"].(float64); ok {
		duration = int64(d)
	}
	// Persist the expiry before granting rights. If the process crashes after
	// this write, cleanup has a durable record to revoke; the reverse ordering
	// could leave an untracked permanent administrator.
	if err := recordElevationExpiry(username, duration); err != nil {
		return 1, "", fmt.Errorf("persist elevation expiry: %w", err)
	}
	out, err := exec.Command("net", "localgroup", "Administrators", username, "/add").CombinedOutput()
	if err != nil {
		_ = removeElevationExpiry(username)
		return 1, string(out), fmt.Errorf("grant elevation: %w", err)
	}
	return 0, fmt.Sprintf("Elevation granted to %s for %d minutes", username, duration), nil
}

func revokeElevation(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	out, err := exec.Command("net", "localgroup", "Administrators", username, "/delete").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("revoke elevation: %w", err)
	}
	if err := removeElevationExpiry(username); err != nil {
		return 1, string(out), fmt.Errorf("persist elevation revocation: %w", err)
	}
	return 0, fmt.Sprintf("Elevation revoked from %s", username), nil
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

// ── Sysinfo / software inventory ──────────────────────────────────────────────

func collectSysinfo() (int, string, error) {
	info := map[string]interface{}{
		"os_name":  runtime.GOOS,
		"arch":     runtime.GOARCH,
		"hostname": func() string { h, _ := os.Hostname(); return h }(),
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("ProcessorNameString"); err == nil {
			info["cpu_model"] = strings.TrimSpace(v)
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("EditionID"); err == nil {
			info["os_edition"] = v
			// EditionID for Home is "Core"/"CoreN"/"CoreSingleLanguage" etc —
			// never literally "Home" (that's only the user-facing product
			// name) — checking for "Home" here always evaluated true.
			info["rdp_capable"] = !strings.HasPrefix(v, "Core")
		}
		k.Close()
	}
	if vm, err := memPkg.VirtualMemory(); err == nil {
		info["ram_total_gb"] = round2(float64(vm.Total) / (1024 * 1024 * 1024))
	}
	if du, err := diskPkg.Usage(`C:\`); err == nil {
		info["disk_total_gb"] = round2(float64(du.Total) / (1024 * 1024 * 1024))
		info["disk_free_gb"] = round2(float64(du.Free) / (1024 * 1024 * 1024))
	}
	// A dedicated /api/agent/sysinfo route (sysinfo() in routes/agent_api.py
	// -> db.update_endpoint_sysinfo) exists for exactly this data -- same
	// gap as COLLECT_USERS/COLLECT_SOFTWARE had (see collectUsers() above):
	// nothing ever actually called it. It's only ever populated once, at
	// enrollment (collectOSInfo() in agent.go, via /enroll's os_info field),
	// so the "Collect System Info" button and the scheduled COLLECT_SYSINFO
	// job both silently never refresh anything after that first snapshot,
	// despite reporting a full JSON payload as job success.
	if _, err := apiPostAuth("/api/agent/sysinfo", info); err != nil {
		return 1, "", fmt.Errorf("report sysinfo: %w", err)
	}
	b, _ := json.Marshal(info)
	return 0, string(b), nil
}

func collectSoftware() (int, string, error) {
	type swEntry struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		Publisher       string `json:"publisher"`
		InstallDate     string `json:"install_date"`
		InstallLocation string `json:"install_location,omitempty"`
		ExecutablePath  string `json:"executable_path,omitempty"`
	}
	seen := make(map[string]bool)
	var software []swEntry
	regPaths := []struct {
		hive registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	for _, rp := range regPaths {
		k, err := registry.OpenKey(rp.hive, rp.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subkeys, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sub := range subkeys {
			sk, err := registry.OpenKey(rp.hive, rp.path+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			pub, _, _ := sk.GetStringValue("Publisher")
			instDate, _, _ := sk.GetStringValue("InstallDate")
			installLocation, _, _ := sk.GetStringValue("InstallLocation")
			displayIcon, _, _ := sk.GetStringValue("DisplayIcon")
			sk.Close()
			if name == "" {
				continue
			}
			key := strings.ToLower(name) + "|" + strings.ToLower(ver)
			if seen[key] {
				continue
			}
			seen[key] = true
			software = append(software, swEntry{
				Name: name, Version: ver, Publisher: pub, InstallDate: instDate,
				InstallLocation: normaliseInventoryPath(installLocation),
				ExecutablePath:  displayIconExecutable(displayIcon),
			})
		}
	}
	// A dedicated /api/agent/software route (report_software() in
	// routes/agent_api.py) has existed for the software_inventory table --
	// same gap as COLLECT_USERS had (see collectUsers() above): nothing
	// ever actually called it. Returning the JSON as the job's own log
	// output (the previous behavior) made it visible in the Jobs tab, but
	// never wrote a single row to software_inventory, so the Software tab
	// stayed empty regardless of how many times this ran successfully.
	if _, err := apiPostAuth("/api/agent/software", map[string]interface{}{"software": software}); err != nil {
		return 1, "", fmt.Errorf("report software: %w", err)
	}
	return 0, fmt.Sprintf("Reported %d software items", len(software)), nil
}

// DisplayIcon is the closest standard Windows uninstall-registry field to the
// actual application binary.  It commonly contains either a quoted executable
// followed by an icon index ("C:\\App\\app.exe",0) or a plain executable.
// Do not guess from UninstallString: that would create a firewall rule for the
// uninstaller rather than for the application the administrator selected.
func displayIconExecutable(value string) string {
	value = strings.TrimSpace(os.ExpandEnv(value))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, `"`) {
		if end := strings.Index(value[1:], `"`); end >= 0 {
			value = value[1 : end+1]
		}
	} else if comma := strings.LastIndex(value, ","); comma >= 0 {
		value = value[:comma]
	}
	value = normaliseInventoryPath(value)
	if !strings.EqualFold(filepath.Ext(value), ".exe") || !filepath.IsAbs(value) {
		return ""
	}
	return value
}

func normaliseInventoryPath(value string) string {
	value = strings.Trim(strings.TrimSpace(os.ExpandEnv(value)), `"`)
	if value == "" || !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Clean(value)
}

// ── Update agent ──────────────────────────────────────────────────────────────

func updateAgent(jobID string, p map[string]interface{}, _ logFn) (int, string, error) {
	// Replacing the service binary stops both the service and its desktop
	// helper.  Doing that in the middle of a remote-control session can leave
	// injected input state behind and, more importantly, interrupts the
	// Winlogon secure desktop while a UAC consent prompt is being observed.
	// Require the operator to disconnect first so an update can never make a
	// UAC interaction appear to have been accepted or dismissed.
	relayMu.Lock()
	remoteActive := relayLive != nil
	relayMu.Unlock()
	if remoteActive {
		return 1, "", fmt.Errorf("agent update refused while remote access is active; disconnect the remote session and retry")
	}

	downloadURL, _ := p["download_url"].(string)
	sha256hex, _ := p["sha256"].(string)
	version, _ := p["version"].(string)
	providerURL, _ := p["credential_provider_url"].(string)
	providerSHA256, _ := p["credential_provider_sha256"].(string)
	if cmp, err := compareAgentVersions(version, agentVersion); err != nil {
		return 1, "", fmt.Errorf("invalid update version: %w", err)
	} else if cmp <= 0 {
		return 0, fmt.Sprintf("Update skipped: installed version %s is not older than %s", agentVersion, version), nil
	}
	if downloadURL == "" {
		return 1, "", fmt.Errorf("missing download_url")
	}
	if runtime.GOOS == "windows" && (providerURL == "" || providerSHA256 == "") {
		return 1, "", fmt.Errorf("Windows update is missing its Credential Provider artifact")
	}
	stageDir, err := jobStageDir(jobID)
	if err != nil {
		return 1, "", err
	}
	os.MkdirAll(stageDir, 0700)
	handoff := false
	defer func() {
		if !handoff {
			_ = os.RemoveAll(stageDir)
		}
	}()
	dest := filepath.Join(stageDir, "warden-agent-new.exe")
	if err := downloadFile(downloadURL, dest, sha256hex); err != nil {
		return 1, "", fmt.Errorf("download failed: %w", err)
	}
	if requireAuthenticodeUpdates() {
		if err := verifyAuthenticode(dest); err != nil {
			return 1, "", fmt.Errorf("update signature verification failed: %w", err)
		}
	}
	providerDest := filepath.Join(stageDir, wardenCredentialProviderAsset)
	if err := downloadFile(providerURL, providerDest, providerSHA256); err != nil {
		return 1, "", fmt.Errorf("Credential Provider download failed: %w", err)
	}
	if requireAuthenticodeUpdates() {
		if err := verifyAuthenticode(providerDest); err != nil {
			return 1, "", fmt.Errorf("Credential Provider signature verification failed: %w", err)
		}
	}
	exePath, err := os.Executable()
	if err != nil {
		return 1, "", fmt.Errorf("get executable path: %w", err)
	}
	batPath := filepath.Join(dataDir, "update.bat")
	backupPath := filepath.Join(dataDir, "warden-agent-backup.exe")
	providerAssetPath := filepath.Join(filepath.Dir(exePath), wardenCredentialProviderAsset)
	providerBackupPath := filepath.Join(stageDir, "WardenCredentialProvider-backup.dll")
	batContent := fmt.Sprintf(
		"@echo off\r\n"+
			"timeout /t 5 /nobreak >nul\r\n"+
			"sc stop WardenAgent >nul 2>&1\r\n"+
			"timeout /t 3 /nobreak >nul\r\n"+
			"copy /y \"%s\" \"%s\" >nul || goto rollback_failed\r\n"+
			"if not exist \"%s\" goto provider_backup_done\r\n"+
			"copy /y \"%s\" \"%s\" >nul || goto rollback\r\n"+
			":provider_backup_done\r\n"+
			"copy /y \"%s\" \"%s\" >nul || goto rollback\r\n"+
			"copy /y \"%s\" \"%s\" >nul || goto rollback\r\n"+
			"del /q \"%s\" >nul 2>&1\r\n"+
			"sc start WardenAgent >nul 2>&1\r\n"+
			"set /a health_wait=0\r\n"+
			":wait_healthy\r\n"+
			"if exist \"%s\" goto success\r\n"+
			"timeout /t 2 /nobreak >nul\r\n"+
			"set /a health_wait+=1\r\n"+
			"if %%health_wait%% lss 30 goto wait_healthy\r\n"+
			":rollback\r\n"+
			"sc stop WardenAgent >nul 2>&1\r\n"+
			"timeout /t 3 /nobreak >nul\r\n"+
			"copy /y \"%s\" \"%s\" >nul\r\n"+
			"if exist \"%s\" (copy /y \"%s\" \"%s\" >nul) else (del /q \"%s\" >nul 2>&1)\r\n"+
			"sc start WardenAgent >nul 2>&1\r\n"+
			"goto cleanup\r\n"+
			":success\r\n"+
			"del /q \"%s\" >nul 2>&1\r\n"+
			"del /q \"%s\" >nul 2>&1\r\n"+
			"goto cleanup\r\n"+
			":rollback_failed\r\n"+
			"sc start WardenAgent >nul 2>&1\r\n"+
			":cleanup\r\n"+
			"rmdir /s /q \"%s\"\r\n"+
			"del /q \"%%~f0\"\r\n",
		exePath, backupPath,
		providerAssetPath, providerAssetPath, providerBackupPath,
		dest, exePath, providerDest, providerAssetPath, updateHealthPath,
		updateHealthPath, backupPath, exePath,
		providerBackupPath, providerBackupPath, providerAssetPath, providerAssetPath,
		backupPath, providerBackupPath, stageDir,
	)
	if err := os.WriteFile(batPath, []byte(batContent), 0600); err != nil {
		return 1, "", fmt.Errorf("write update script: %w", err)
	}
	if err := exec.Command("cmd", "/c", "start", "", batPath).Start(); err != nil {
		return 1, "", fmt.Errorf("launch update script: %w", err)
	}
	handoff = true // update.bat owns cleanup after copying the staged binary
	return 0, fmt.Sprintf("Update to version %s initiated", version), nil
}

func compareAgentVersions(a, b string) (int, error) {
	parse := func(value string) ([3]int, error) {
		var result [3]int
		parts := strings.Split(strings.TrimSpace(value), ".")
		if len(parts) != 3 {
			return result, fmt.Errorf("version %q must be major.minor.patch", value)
		}
		for i, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 {
				return result, fmt.Errorf("version %q contains a non-numeric component", value)
			}
			result[i] = n
		}
		return result, nil
	}
	av, err := parse(a)
	if err != nil {
		return 0, err
	}
	bv, err := parse(b)
	if err != nil {
		return 0, err
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1, nil
		}
		if av[i] > bv[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func rotateTLSPins(p map[string]interface{}) (int, string, error) {
	raw, ok := p["fingerprints"].([]interface{})
	if !ok || len(raw) == 0 || len(raw) > 3 {
		return 1, "", fmt.Errorf("fingerprints must contain between 1 and 3 SHA-256 values")
	}
	values := make([]string, 0, len(raw))
	newSet := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		value, ok := item.(string)
		if !ok {
			return 1, "", fmt.Errorf("fingerprints must be strings")
		}
		fp, err := normalizeFingerprint(value)
		if err != nil {
			return 1, "", err
		}
		if _, exists := newSet[fp]; !exists {
			newSet[fp] = struct{}{}
			values = append(values, fp)
		}
	}
	overlap := false
	for fp := range currentPinnedFingerprints() {
		if _, ok := newSet[fp]; ok {
			overlap = true
			break
		}
	}
	if !overlap {
		return 1, "", fmt.Errorf("new TLS pin set must overlap the currently trusted set")
	}
	c := getConfig()
	c.CertFingerprints = values
	c.CertFingerprint = values[0]
	if err := saveConfig(c); err != nil {
		return 1, "", err
	}
	if err := replacePinnedFingerprints(values); err != nil {
		return 1, "", err
	}
	return 0, fmt.Sprintf("Installed %d TLS certificate pin(s)", len(values)), nil
}

// ── Peripheral policy ─────────────────────────────────────────────────────────

func setPeripheralPolicy(p map[string]interface{}) (int, string, error) {
	policyType, _ := p["policy_type"].(string)
	setStart := func(svc string, start uint32) error {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\`+svc, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.SetDWordValue("Start", start)
	}
	switch policyType {
	case "block_usb_storage":
		if err := setStart("USBSTOR", 4); err != nil {
			return 1, "", fmt.Errorf("block_usb_storage: %w", err)
		}
	case "allow_usb_storage":
		if err := setStart("USBSTOR", 3); err != nil {
			return 1, "", fmt.Errorf("allow_usb_storage: %w", err)
		}
	// "block_all_usb" (USBSTOR + usbhub) intentionally removed: usbhub.sys is
	// the USB hub driver itself, not specific to storage — disabling it takes
	// out every USB device on the machine, including keyboard/mouse, on the
	// next reboot. Blocking mass storage only (USBSTOR) already covers the
	// legitimate "no flash drives" use case without that risk.
	default:
		return 1, "", fmt.Errorf("policy_type '%s' not allowed", policyType)
	}
	return 0, fmt.Sprintf("Policy %s applied", policyType), nil
}

// ── Remote access ─────────────────────────────────────────────────────────────

func setupRemoteAccess(_ string, p map[string]interface{}) (int, string, error) {
	relayURL, _ := p["relay_url"].(string)
	if relayURL == "" {
		return 1, "", fmt.Errorf("missing relay_url in payload")
	}
	// All the validation/rejection paths below return before ever reaching
	// runRelaySession's goroutine — reportRelayFailure only used to be
	// called from failures WITHIN that goroutine, so a rejection here
	// (e.g. "already running", the most common one: a previous session's
	// goroutine hasn't finished tearing down yet when a second
	// SETUP_REMOTE_ACCESS lands moments later) left the browser side with
	// no report at all, stuck showing "Waiting for device..." for the
	// full 60s ws_proxy timeout instead of learning the real reason in
	// seconds. Report every failure path here too, not just the async ones.
	sessionID := sessionIDFromRelayURL(relayURL)
	fail := func(reason string, err error) (int, string, error) {
		reportRelayFailure(sessionID, reason)
		return 1, "", err
	}
	if apiKey == "" {
		return fail("agent API key not loaded", fmt.Errorf("agent API key not loaded"))
	}
	consentRequired, _ := p["consent_required"].(bool)
	consentTitle, _ := p["consent_title"].(string)
	consentMessage, _ := p["consent_message"].(string)
	requestedAccess := make([]string, 0, 6)
	if raw, ok := p["requested_access"].([]interface{}); ok {
		for _, item := range raw {
			if label, ok := item.(string); ok && strings.TrimSpace(label) != "" {
				requestedAccess = append(requestedAccess, strings.TrimSpace(label))
			}
		}
	}
	if consentRequired {
		helperName, _ := p["helper_name"].(string)
		reason, _ := p["reason"].(string)
		if helperName == "" {
			helperName = "A Warden technician"
		}
		if reason == "" {
			reason = "Interactive support"
		}
		if err := requestRemoteConsent(sessionID, helperName, reason, consentTitle, consentMessage, requestedAccess); err != nil {
			return fail(err.Error(), err)
		}
	} else {
		reportRemoteConsent(sessionID, "not_required")
	}
	parsed, err := url.Parse(relayURL)
	if err != nil {
		return fail(fmt.Sprintf("invalid relay_url: %v", err), fmt.Errorf("invalid relay_url: %w", err))
	}
	server, err := url.Parse(serverURL())
	if err != nil {
		return fail(fmt.Sprintf("invalid configured server URL: %v", err), fmt.Errorf("invalid configured server URL: %w", err))
	}
	if parsed.Scheme != "wss" || !strings.EqualFold(
		parsed.Host, server.Host,
	) || parsed.RawQuery != "" || !strings.HasPrefix(
		parsed.Path, "/agent-relay/",
	) {
		return fail("relay_url is not an approved Warden wss URL", fmt.Errorf("relay_url is not an approved Warden wss URL"))
	}
	if err := startRemoteRelay(relayURL, apiKey, "Remote support is connected", consentMessage); err != nil {
		return fail(err.Error(), err)
	}
	return 0, fmt.Sprintf("Remote relay session connecting to %s", relayURL), nil
}

func removeRemoteAccess() (int, string, error) {
	stopRemoteRelay()
	return 0, "Remote access stopped", nil
}

// ── Compliance scan ───────────────────────────────────────────────────────────

func complianceScan(jobID string, p map[string]interface{}) (int, string, error) {
	checks := []string{
		"bitlocker_enabled", "firewall_enabled", "antivirus_present",
		"screen_lock_enabled", "auto_update_enabled",
		"password_min_length", "guest_account_disabled",
	}
	if raw, ok := p["checks"].([]interface{}); ok && len(raw) > 0 {
		checks = nil
		for _, c := range raw {
			if s, ok := c.(string); ok {
				checks = append(checks, s)
			}
		}
	}

	type checkResult struct {
		Check  string `json:"check"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	var results []checkResult
	for _, name := range checks {
		results = append(results, runComplianceCheck(name))
	}

	passed := 0
	for _, r := range results {
		if r.Status == "pass" {
			passed++
		}
	}
	total := len(results)
	score := 0
	if total > 0 {
		score = passed * 100 / total
	}
	overall := "non_compliant"
	if passed == total {
		overall = "compliant"
	}

	policyID, _ := p["policy_id"].(string)
	// Unlike getEventLogs/filePull, the full results are also returned in
	// log_output below as a fallback, so a POST failure here doesn't lose
	// the data outright -- but it does mean the dedicated compliance_results
	// table (and anything reading from it, e.g. the compliance dashboard)
	// silently misses this scan. Surface the error in the log rather than
	// discarding it, without failing the job since the scan itself succeeded.
	postNote := ""
	if _, err := apiPostAuth("/api/agent/compliance-result", map[string]interface{}{
		"job_id":         jobID,
		"policy_id":      policyID,
		"overall_status": overall,
		"score":          score,
		"results":        results,
	}); err != nil {
		postNote = fmt.Sprintf(" (warning: failed to report to compliance dashboard: %v)", err)
	}

	b, _ := json.Marshal(map[string]interface{}{
		"overall_status": overall,
		"score":          score,
		"results":        results,
	})
	return 0, string(b) + postNote, nil
}

func runComplianceCheck(name string) struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
} {
	type R = struct {
		Check  string `json:"check"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	pass := func(d string) R { return R{name, "pass", d} }
	fail := func(d string) R { return R{name, "fail", d} }
	errR := func(d string) R { return R{name, "error", d} }

	switch name {
	case "bitlocker_enabled":
		out, err := exec.Command("manage-bde", "-status", "C:").Output()
		if err != nil {
			return errR("manage-bde failed")
		}
		s := string(out)
		if strings.Contains(s, "Protection On") {
			return pass("BitLocker is enabled")
		}
		return fail("BitLocker is not enabled on C:")

	case "firewall_enabled":
		out, err := exec.Command("powershell", "-NonInteractive", "-Command",
			"(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Count").Output()
		if err != nil {
			return errR("Get-NetFirewallProfile failed")
		}
		cnt := strings.TrimSpace(string(out))
		if cnt == "0" || cnt == "" {
			return pass("All firewall profiles enabled")
		}
		return fail(cnt + " firewall profile(s) disabled")

	case "antivirus_present":
		out, err := exec.Command("powershell", "-NonInteractive", "-Command",
			"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ConvertTo-Json").Output()
		if err != nil {
			return errR("Get-CimInstance failed")
		}
		s := strings.TrimSpace(string(out))
		if s != "" && s != "null" && s != "[]" {
			if len(s) > 200 {
				s = s[:200]
			}
			return pass(s)
		}
		return fail("No antivirus product detected")

	case "screen_lock_enabled":
		k, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.QUERY_VALUE)
		if err != nil {
			return errR("registry open failed")
		}
		defer k.Close()
		timeoutStr, _, _ := k.GetStringValue("ScreenSaveTimeOut")
		secure, _, _ := k.GetStringValue("ScreenSaverIsSecure")
		timeoutSec, _ := strconv.Atoi(timeoutStr)
		timeoutMin := timeoutSec / 60
		if secure == "1" && timeoutMin <= 15 && timeoutMin > 0 {
			return pass(fmt.Sprintf("Screen lock: %dmin, secure=1", timeoutMin))
		}
		return fail(fmt.Sprintf("Screen lock: %dmin, secure=%s", timeoutMin, secure))

	case "auto_update_enabled":
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, registry.QUERY_VALUE)
		if err != nil {
			return pass("Auto update enabled (no policy override)")
		}
		defer k.Close()
		noAuto, _, _ := k.GetIntegerValue("NoAutoUpdate")
		if noAuto == 0 {
			return pass("Auto update enabled")
		}
		return fail("Auto update disabled by policy")

	case "password_min_length":
		out, _ := exec.Command("net", "accounts").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Minimum password length") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					minLen, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
					if minLen >= 8 {
						return pass(fmt.Sprintf("Minimum password length: %d", minLen))
					}
					return fail(fmt.Sprintf("Minimum password length: %d (requires >=8)", minLen))
				}
			}
		}
		return errR("could not determine password policy")

	case "guest_account_disabled":
		out, _ := exec.Command("net", "user", "Guest").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Account active") {
				if strings.Contains(line, "Yes") {
					return fail("Guest account is active")
				}
				return pass("Guest account disabled")
			}
		}
		return pass("Guest account not found (assumed disabled)")

	default:
		return errR(fmt.Sprintf("Unknown check: %s", name))
	}
}

// ── File operations ───────────────────────────────────────────────────────────

func filePush(p map[string]interface{}) (int, string, error) {
	destPath, _ := p["path"].(string)
	contentB64, _ := p["content_b64"].(string)
	if destPath == "" || contentB64 == "" {
		return 1, "", fmt.Errorf("missing path or content_b64")
	}
	// Reject oversized input before DecodeString allocates its destination.
	// The payload is server-signed, but a configuration mistake should not be
	// able to exhaust memory in the SYSTEM service.
	if int64(len(contentB64)) > (maxRemoteTransferBytes*4/3)+4 {
		return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
	}
	safeRoots := []string{
		`c:\programdata\wardenagent\`,
		`c:\windows\temp\`,
		`c:\users\public\`,
		// Remote-view drag-and-drop may target the active Explorer folder
		// within a user's profile instead of always forcing Public Desktop.
		// resolveAllowedPath still canonicalizes the destination and prevents
		// traversal outside C:\Users.
		`c:\users\`,
	}
	destPath, err := resolveAllowedPath(destPath, safeRoots)
	if err != nil {
		return 1, "", err
	}
	content, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return 1, "", fmt.Errorf("base64 decode: %w", err)
	}
	if int64(len(content)) > maxRemoteTransferBytes {
		return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
	}
	os.MkdirAll(filepath.Dir(destPath), 0700)
	if err := os.WriteFile(destPath, content, 0600); err != nil {
		return 1, "", fmt.Errorf("write file: %w", err)
	}
	return 0, fmt.Sprintf("File written to %s (%d bytes)", destPath, len(content)), nil
}

func filePull(jobID string, p map[string]interface{}) (int, string, error) {
	srcPath, _ := p["path"].(string)
	if srcPath == "" {
		return 1, "", fmt.Errorf("missing path")
	}
	safeRoots := []string{
		`c:\programdata\wardenagent\`,
		`c:\windows\logs\`,
		`c:\windows\temp\`,
		`c:\users\public\`,
		// Remote-view downloads may select a file in the interactive user's
		// profile. resolveAllowedPath canonicalizes it and prevents escaping
		// C:\Users through traversal.
		`c:\users\`,
	}
	srcPath, err := resolveAllowedPath(srcPath, safeRoots)
	if err != nil {
		return 1, "", err
	}
	info, err := os.Stat(srcPath)
	if err != nil {
		return 1, "", fmt.Errorf("stat file: %w", err)
	}
	var content []byte
	downloadName := filepath.Base(srcPath)
	if info.IsDir() {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		err = filepath.Walk(srcPath, func(path string, entry os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Mode().IsRegular() {
				return nil
			}
			rel, relErr := filepath.Rel(srcPath, path)
			if relErr != nil {
				return relErr
			}
			w, createErr := zw.Create(filepath.ToSlash(rel))
			if createErr != nil {
				return createErr
			}
			f, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			_, copyErr := io.Copy(w, io.LimitReader(f, maxRemoteTransferBytes+1))
			f.Close()
			if copyErr != nil {
				return copyErr
			}
			if buf.Len() > maxRemoteTransferBytes {
				return fmt.Errorf("folder is too large for remote transfer (max 8 MB compressed)")
			}
			return nil
		})
		closeErr := zw.Close()
		if err != nil {
			return 1, "", err
		}
		if closeErr != nil {
			return 1, "", closeErr
		}
		content = buf.Bytes()
		downloadName += ".zip"
	} else if info.Mode().IsRegular() {
		if info.Size() > maxRemoteTransferBytes {
			return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
		}
		content, err = os.ReadFile(srcPath)
		if err != nil {
			return 1, "", fmt.Errorf("read file: %w", err)
		}
	} else {
		return 1, "", fmt.Errorf("path is not a regular file or folder")
	}
	if len(content) > maxRemoteTransferBytes {
		return 1, "", fmt.Errorf("file is too large for remote transfer (max 8 MB)")
	}
	contentB64 := base64.StdEncoding.EncodeToString(content)
	// The pulled bytes only ever exist in this POST -- log_output below is
	// just a summary sentence, not the actual file content. Discarding this
	// error used to mean a failed delivery still reported job success with
	// a plausible-looking message, silently losing the file.
	if _, err := apiPostAuth("/api/agent/file-content", map[string]interface{}{
		"job_id":        jobID,
		"path":          srcPath,
		"download_name": downloadName,
		"content_b64":   contentB64,
		"size_bytes":    len(content),
	}); err != nil {
		return 1, "", fmt.Errorf("report file content: %w", err)
	}
	return 0, fmt.Sprintf("File %s pulled (%d bytes)", srcPath, len(content)), nil
}

// capturePackets creates a tightly bounded PCAPNG capture using Pktmon, the
// packet monitor already shipped with supported Windows releases.  Keeping the
// orchestration here means Warden still ships one agent executable and no
// unsigned capture driver.  Captures are deliberately capped at 8 MiB because
// they use the same authenticated, tenant-scoped result channel as FILE_PULL.
func capturePackets(jobID string, p map[string]interface{}, log logFn) (int, string, error) {
	if !packetCaptureMu.TryLock() {
		return 1, "", fmt.Errorf("another Warden packet capture is already running")
	}
	defer packetCaptureMu.Unlock()

	duration := 30
	maxSizeMB := 4
	port := 0
	if value, ok := p["duration_seconds"].(float64); ok {
		duration = int(value)
	}
	if value, ok := p["max_size_mb"].(float64); ok {
		maxSizeMB = int(value)
	}
	if value, ok := p["port"].(float64); ok {
		port = int(value)
	}
	protocol, _ := p["protocol"].(string)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "any"
	}
	remoteIP, _ := p["remote_ip"].(string)
	remoteIP = strings.TrimSpace(remoteIP)
	if duration < 5 || duration > 120 || maxSizeMB < 1 || maxSizeMB > 8 || port < 0 || port > 65535 {
		return 1, "", fmt.Errorf("invalid packet capture limits")
	}
	if protocol != "any" && protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return 1, "", fmt.Errorf("invalid packet capture protocol")
	}
	if remoteIP != "" {
		if strings.Contains(remoteIP, "/") {
			if _, _, err := net.ParseCIDR(remoteIP); err != nil {
				return 1, "", fmt.Errorf("invalid remote IP or CIDR")
			}
		} else if net.ParseIP(remoteIP) == nil {
			return 1, "", fmt.Errorf("invalid remote IP or CIDR")
		}
	}
	if _, err := exec.LookPath("pktmon.exe"); err != nil {
		return 1, "", fmt.Errorf("Windows Packet Monitor is unavailable: %w", err)
	}
	// Pktmon owns one machine-wide ETW session and one shared filter list. Never
	// stop or overwrite a capture/filter configured by an administrator or
	// another diagnostic product. logman gives us a locale-independent exit
	// status for the named PktMon ETW session.
	if err := exec.Command("logman.exe", "query", "PktMon", "-ets").Run(); err == nil {
		return 1, "", fmt.Errorf("Windows Packet Monitor is already in use")
	}
	filterList, filterErr := boundedCombinedOutput(exec.Command("pktmon.exe", "filter", "list"))
	if filterErr != nil {
		return 1, "", fmt.Errorf("inspect packet capture filters: %w", filterErr)
	}
	if !strings.Contains(strings.ToLower(string(filterList)), "none") {
		return 1, "", fmt.Errorf("Windows Packet Monitor has existing filters; clear them before starting a Warden capture")
	}

	stageDir, err := jobStageDir(jobID)
	if err != nil {
		return 1, "", err
	}
	if err := createSystemOnlyDirectory(stageDir); err != nil {
		return 1, "", fmt.Errorf("secure capture staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)
	etlPath := filepath.Join(stageDir, "capture.etl")
	pcapPath := filepath.Join(stageDir, "capture.pcapng")

	// We verified above that the global Pktmon session is idle and its filter
	// list is empty, so cleanup below removes only the filter created here.
	defer exec.Command("pktmon.exe", "filter", "remove").Run()
	filterArgs := []string{"filter", "add", "WardenCapture"}
	if remoteIP != "" {
		filterArgs = append(filterArgs, "-i", remoteIP)
	}
	if port > 0 {
		filterArgs = append(filterArgs, "-p", strconv.Itoa(port))
	}
	if protocol != "any" {
		filterArgs = append(filterArgs, "-t", strings.ToUpper(protocol))
	}
	if len(filterArgs) > 3 {
		if out, filterErr := boundedCombinedOutput(exec.Command("pktmon.exe", filterArgs...)); filterErr != nil {
			return 1, "", fmt.Errorf("configure packet capture filter: %w (%s)", filterErr, strings.TrimSpace(string(out)))
		}
	}
	startArgs := []string{"start", "--capture", "--pkt-size", "0", "--file-name", etlPath, "--file-size", strconv.Itoa(maxSizeMB)}
	if out, startErr := boundedCombinedOutput(exec.Command("pktmon.exe", startArgs...)); startErr != nil {
		return 1, "", fmt.Errorf("start packet capture: %w (%s)", startErr, strings.TrimSpace(string(out)))
	}
	defer exec.Command("pktmon.exe", "stop").Run()
	log(fmt.Sprintf("Packet capture started for %d seconds (maximum %d MiB)", duration, maxSizeMB))
	time.Sleep(time.Duration(duration) * time.Second)
	if out, stopErr := boundedCombinedOutput(exec.Command("pktmon.exe", "stop")); stopErr != nil {
		return 1, "", fmt.Errorf("stop packet capture: %w (%s)", stopErr, strings.TrimSpace(string(out)))
	}
	if out, convertErr := boundedCombinedOutput(exec.Command("pktmon.exe", "etl2pcap", etlPath, "--out", pcapPath)); convertErr != nil {
		return 1, "", fmt.Errorf("convert capture to PCAPNG: %w (%s)", convertErr, strings.TrimSpace(string(out)))
	}
	content, err := os.ReadFile(pcapPath)
	if err != nil {
		return 1, "", fmt.Errorf("read PCAPNG capture: %w", err)
	}
	if len(content) == 0 || len(content) > maxRemoteTransferBytes {
		return 1, "", fmt.Errorf("capture size %d is outside the 1 byte to 8 MiB delivery limit", len(content))
	}
	if len(content) < 4 || !bytes.Equal(content[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		return 1, "", fmt.Errorf("converted capture is not a valid PCAPNG stream")
	}
	downloadName := fmt.Sprintf("warden-capture-%s.pcapng", time.Now().UTC().Format("20060102-150405"))
	if _, err := apiPostAuth("/api/agent/file-content", map[string]interface{}{
		"job_id": jobID, "path": pcapPath, "download_name": downloadName,
		"content_b64": base64.StdEncoding.EncodeToString(content), "size_bytes": len(content),
	}); err != nil {
		return 1, "", fmt.Errorf("upload packet capture: %w", err)
	}
	return 0, fmt.Sprintf("Captured %d bytes to %s", len(content), downloadName), nil
}

func listDirectory(p map[string]interface{}) (int, string, error) {
	dirPath, _ := p["path"].(string)
	type item struct {
		Name  string `json:"name"`
		Path  string `json:"path"`
		IsDir bool   `json:"is_dir"`
		Size  int64  `json:"size"`
	}
	roots := remoteUserFolderRoots()
	if dirPath == "" || dirPath == "::folders::" {
		items := make([]item, 0, len(roots))
		for _, root := range roots {
			items = append(items, item{
				Name: filepath.Base(filepath.Dir(root)) + " — " + filepath.Base(root),
				Path: root, IsDir: true,
			})
		}
		result, _ := json.Marshal(map[string]interface{}{"path": "::folders::", "items": items})
		return 0, string(result), nil
	}
	resolved, err := resolveAllowedPath(dirPath, roots)
	if err != nil {
		return 1, "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return 1, "", fmt.Errorf("folder not found")
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return 1, "", err
	}
	const maxDirectoryEntries = 2000
	truncated := len(entries) > maxDirectoryEntries
	if truncated {
		entries = entries[:maxDirectoryEntries]
	}
	items := make([]item, 0, len(entries))
	for _, entry := range entries {
		child := filepath.Join(resolved, entry.Name())
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		items = append(items, item{entry.Name(), child, entry.IsDir(), entryInfo.Size()})
	}
	result, _ := json.Marshal(map[string]interface{}{
		"path": resolved, "items": items, "truncated": truncated,
	})
	return 0, string(result), nil
}

func remoteUserFolderRoots() []string {
	profiles, _ := os.ReadDir(`C:\Users`)
	var roots []string
	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}
		for _, folder := range []string{"Desktop", "Documents", "Downloads"} {
			path := filepath.Join(`C:\Users`, profile.Name(), folder)
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				roots = append(roots, path)
			}
		}
	}
	return roots
}

func getEventLogs(jobID string, p map[string]interface{}) (int, string, error) {
	logName, _ := p["log_name"].(string)
	if logName == "" {
		logName = "System"
	}
	if logName != "System" && logName != "Application" && logName != "Security" {
		return 1, "", fmt.Errorf("log_name must be System, Application, or Security")
	}
	maxEvents := 50
	if m, ok := p["max_events"].(float64); ok && m > 0 {
		if int(m) <= 500 {
			maxEvents = int(m)
		} else {
			maxEvents = 500
		}
	}
	hours := 24
	if h, ok := p["hours"].(float64); ok && h > 0 {
		if int(h) <= 168 {
			hours = int(h)
		} else {
			hours = 168
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NonInteractive", "-Command",
		fmt.Sprintf(
			"Get-WinEvent -LogName %s -MaxEvents %d | Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-%d)} | Select-Object TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Json -Compress",
			logName, maxEvents, hours,
		))
	out, cmdErr := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return 1, "", fmt.Errorf("Get-WinEvent timed out after 45 seconds")
	}
	eventsJSON := strings.TrimSpace(string(out))
	if eventsJSON == "" {
		if cmdErr != nil {
			return 1, "", fmt.Errorf("Get-WinEvent: %w", cmdErr)
		}
		eventsJSON = "[]"
	}
	// The events only ever exist in this POST -- log_output below is just a
	// summary sentence, not the actual event data. Discarding this error
	// used to mean a failed delivery still reported job success with a
	// plausible-looking message, silently losing the collected events.
	if _, err := apiPostAuth("/api/agent/event-logs", map[string]interface{}{
		"job_id":      jobID,
		"log_name":    logName,
		"events_json": eventsJSON,
	}); err != nil {
		return 1, "", fmt.Errorf("report event logs: %w", err)
	}
	return 0, fmt.Sprintf("Collected event log entries from %s", logName), nil
}

func windowsUpdate(p map[string]interface{}) (int, string, error) {
	action, _ := p["action"].(string)
	if action == "" {
		action = "check"
	}
	switch action {
	case "check":
		out, err := exec.Command("UsoClient", "StartScan").CombinedOutput()
		if err != nil {
			return commandExitCode(err), string(out), fmt.Errorf("Windows Update scan: %w", err)
		}
		count, err := reportWindowsPatchInventory()
		if err != nil {
			return 1, "Windows Update scan triggered, but inventory reporting failed", err
		}
		return 0, fmt.Sprintf("Windows Update scan triggered; reported %d pending updates", count), nil
	case "install":
		allowed := map[string]bool{"Critical": true, "Important": true, "Moderate": true, "Low": true, "Unspecified": true}
		severities := []string{}
		if raw, ok := p["severities"].([]interface{}); ok {
			for _, value := range raw {
				if text, ok := value.(string); ok && allowed[text] {
					severities = append(severities, text)
				}
			}
		}
		if len(severities) == 0 {
			severities = []string{"Critical", "Important", "Moderate", "Low", "Unspecified"}
		}
		quoted := make([]string, 0, len(severities))
		for _, severity := range severities {
			quoted = append(quoted, "'"+severity+"'")
		}
		script := `$ErrorActionPreference='Stop'; $allowed=@(` + strings.Join(quoted, ",") + `); ` +
			`$session=New-Object -ComObject Microsoft.Update.Session; $search=$session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0"); ` +
			`$selected=New-Object -ComObject Microsoft.Update.UpdateColl; foreach($u in $search.Updates){ $s=$(if($u.MsrcSeverity){$u.MsrcSeverity}else{'Unspecified'}); if($allowed -contains $s){ if(-not $u.EulaAccepted){$u.AcceptEula()}; [void]$selected.Add($u) } }; ` +
			`if($selected.Count -eq 0){ Write-Output 'No approved updates are applicable'; exit 0 }; ` +
			`$downloader=$session.CreateUpdateDownloader(); $downloader.Updates=$selected; $download=$downloader.Download(); ` +
			`$ready=New-Object -ComObject Microsoft.Update.UpdateColl; foreach($u in $selected){if($u.IsDownloaded){[void]$ready.Add($u)}}; ` +
			`if($ready.Count -eq 0){throw 'No approved updates downloaded'}; $installer=$session.CreateUpdateInstaller(); $installer.Updates=$ready; $result=$installer.Install(); ` +
			`Write-Output ("Installed {0} approved update(s); result={1}; reboot={2}" -f $ready.Count,$result.ResultCode,$result.RebootRequired); if($result.ResultCode -gt 3){exit 1}`
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		if ctx.Err() != nil {
			return 1, string(out), fmt.Errorf("Windows Update installation timed out")
		}
		if err != nil {
			return commandExitCode(err), string(out), fmt.Errorf("Windows Update install: %w", err)
		}
		_, _ = reportWindowsPatchInventory()
		return 0, strings.TrimSpace(string(out)), nil
	default:
		return 1, "", fmt.Errorf("action must be 'check' or 'install'")
	}
}

func collectNetworkFlows() (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// Bounded connection snapshots provide process-aware analysis without
	// retaining payloads. Future WFP rule-hit telemetry uses the same API.
	script := `$ErrorActionPreference='SilentlyContinue'; ` +
		`$items=@(); Get-NetTCPConnection | Select-Object -First 750 | ForEach-Object { ` +
		`$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; ` +
		`$items += [pscustomobject]@{protocol='tcp';direction='outbound';local_address=$_.LocalAddress;local_port=$_.LocalPort;remote_address=$_.RemoteAddress;remote_port=$_.RemotePort;process_id=$_.OwningProcess;process_name=$p.ProcessName;process_path=$p.Path;state=[string]$_.State} }; ` +
		`Get-NetUDPEndpoint | Select-Object -First 250 | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; ` +
		`$items += [pscustomobject]@{protocol='udp';direction='outbound';local_address=$_.LocalAddress;local_port=$_.LocalPort;remote_address=$null;remote_port=$null;process_id=$_.OwningProcess;process_name=$p.ProcessName;process_path=$p.Path;state='Listening'} }; ` +
		`ConvertTo-Json -InputObject $items -Compress -Depth 4`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if ctx.Err() != nil {
		return 1, "", fmt.Errorf("collect network flows: timed out")
	}
	if err != nil {
		return commandExitCode(err), string(out), fmt.Errorf("collect network flows: %w", err)
	}
	var flows []map[string]interface{}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) > 0 && string(trimmed) != "null" {
		if err := json.Unmarshal(trimmed, &flows); err != nil {
			return 1, "", fmt.Errorf("decode network flows: %w", err)
		}
	}
	if len(flows) > 1000 {
		flows = flows[:1000]
	}
	if _, err := apiPostAuth("/api/agent/network-flows", map[string]interface{}{"flows": flows}); err != nil {
		return 1, "", fmt.Errorf("report network flows: %w", err)
	}
	return 0, fmt.Sprintf("Reported %d network flow observations", len(flows)), nil
}

func reportWindowsPatchInventory() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Microsoft.Update.Session is available on supported Windows editions and
	// returns authoritative applicability data without relying on locale-specific
	// command output. ConvertTo-Json receives an explicit array so zero, one and
	// many updates all share the same wire shape.
	script := `$session = New-Object -ComObject Microsoft.Update.Session; ` +
		`$result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0"); ` +
		`$items = @($result.Updates | ForEach-Object { [pscustomobject]@{ ` +
		`update_id=$_.Identity.UpdateID; title=$_.Title; kb_articles=@($_.KBArticleIDs); ` +
		`severity=$(if ($_.MsrcSeverity) { $_.MsrcSeverity } else { 'Unspecified' }); ` +
		`categories=@($_.Categories | ForEach-Object { $_.Name }); ` +
		`reboot_required=[bool]$_.RebootRequired } }); ` +
		`ConvertTo-Json -InputObject $items -Compress -Depth 5`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if ctx.Err() != nil {
		return 0, fmt.Errorf("query pending updates: timed out")
	}
	if err != nil {
		return 0, fmt.Errorf("query pending updates: %w: %s", err, strings.TrimSpace(string(out)))
	}

	updates := make([]map[string]interface{}, 0)
	if trimmed := bytes.TrimSpace(out); len(trimmed) > 0 && string(trimmed) != "null" {
		if err := json.Unmarshal(trimmed, &updates); err != nil {
			return 0, fmt.Errorf("decode pending updates: %w", err)
		}
	}
	if len(updates) > 500 {
		updates = updates[:500]
	}
	if _, err := apiPostAuth("/api/agent/patch-inventory", map[string]interface{}{
		"updates": updates,
	}); err != nil {
		return 0, fmt.Errorf("report pending updates: %w", err)
	}
	return len(updates), nil
}

// runCmd is a fire-and-forget helper for simple commands (e.g., icacls).
func runCmd(name string, args ...string) {
	exec.Command(name, args...).Run()
}

var canonicalJobID = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

func jobStageDir(jobID string) (string, error) {
	if !canonicalJobID.MatchString(jobID) {
		return "", fmt.Errorf("job_id must be a canonical UUID")
	}
	return filepath.Join(stagingDir, strings.ToLower(jobID)), nil
}

func resolveAllowedPath(path string, roots []string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	cleaned, err := canonicalPath(path)
	if err != nil {
		return "", fmt.Errorf("canonicalize path: %w", err)
	}
	for _, root := range roots {
		rootAbs, err := canonicalPath(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootAbs, cleaned)
		if err == nil && rel != ".." &&
			!strings.HasPrefix(rel, `..\`) && !filepath.IsAbs(rel) {
			return cleaned, nil
		}
	}
	return "", fmt.Errorf("path outside allowed locations: %s", path)
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	current := absolute
	var suffix []string
	for {
		if _, statErr := os.Stat(current); statErr == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %s", path)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func commandExitCode(err error) int {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}
