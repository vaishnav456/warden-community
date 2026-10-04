package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	windowsPkg "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

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
	if err := addDeviceRequestProof(req, nil); err != nil {
		return "", err
	}
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
		mode := "--user-notification"
		if requireAck {
			mode = "--user-announcement"
		}
		helper, err := launchInteractiveHelper(exePath, []string{mode, title, announcement, severity})
		if err != nil {
			return 1, "", fmt.Errorf("display announcement: %w", err)
		}
		if requireAck {
			if code, finished := helper.wait(5 * time.Minute); !finished {
				helper.terminate(2 * time.Second)
				return 1, "", fmt.Errorf("announcement acknowledgement timed out")
			} else if code != 0 {
				return 1, "", fmt.Errorf("announcement was not acknowledged")
			}
		} else {
			go func() {
				if _, finished := helper.wait(20 * time.Second); !finished {
					helper.terminate(2 * time.Second)
				}
			}()
		}
		applied = append(applied, "user announcement")
	}
	if len(applied) == 0 {
		return 1, "", fmt.Errorf("no device experience changes supplied")
	}
	return 0, "Applied " + strings.Join(applied, ", "), nil
}
