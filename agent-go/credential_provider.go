package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	wardenCredentialProviderCLSID = `{7C0EAF41-2D67-4F6B-A562-6BF97BD19EE1}`
	wardenCredentialProviderDir   = `C:\Program Files\Warden\CredentialProvider`
	wardenCredentialProviderAsset = "WardenCredentialProvider.dll"
)

// ensureCredentialProviderInstalled repairs or installs the provider shipped
// beside the running agent.  This is intentionally part of normal service
// startup, not only the interactive `install` command: self-updates replace
// an already-installed service and therefore never execute that command.
// The build-pinned hash keeps this repair path fail-closed if either the
// staged DLL or its registered copy was substituted.
func ensureCredentialProviderInstalled() error {
	expected := strings.ToLower(strings.TrimSpace(buildCredentialProviderSHA256))
	if expected == "" || credentialProviderInstalled() {
		return nil
	}
	return installCredentialProviderFromInstaller()
}

func installCredentialProviderFromInstaller() error {
	expected := strings.ToLower(strings.TrimSpace(buildCredentialProviderSHA256))
	if expected == "" {
		// Older/dev builds that do not advertise a provider artifact remain
		// installable, but correctly omit WARDEN_SIGNIN from capabilities.
		return nil
	}
	decodedHash, decodeErr := hex.DecodeString(expected)
	if decodeErr != nil || len(decodedHash) != sha256.Size {
		return fmt.Errorf("invalid build-pinned Credential Provider hash")
	}
	curExe, err := os.Executable()
	if err != nil {
		return err
	}
	source := filepath.Join(filepath.Dir(curExe), wardenCredentialProviderAsset)
	actual, err := fileSHA256(source)
	if err != nil {
		return fmt.Errorf("read packaged Credential Provider: %w", err)
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("packaged Credential Provider hash mismatch")
	}
	if requireAuthenticodeUpdates() {
		if err := verifyAuthenticode(source); err != nil {
			return fmt.Errorf("Credential Provider signature verification failed: %w", err)
		}
	}
	if err := os.MkdirAll(wardenCredentialProviderDir, 0755); err != nil {
		return err
	}
	target := filepath.Join(
		wardenCredentialProviderDir,
		"WardenCredentialProvider-"+actual[:16]+".dll",
	)
	if _, err := os.Stat(target); os.IsNotExist(err) {
		tmp := target + ".tmp"
		if err := copyFile(source, tmp); err != nil {
			return err
		}
		if copied, err := fileSHA256(tmp); err != nil || !strings.EqualFold(copied, expected) {
			_ = os.Remove(tmp)
			return fmt.Errorf("Credential Provider changed while copying")
		}
		if err := os.Rename(tmp, target); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}

	// Secure the file before making LogonUI aware of the provider. A failed
	// ACL operation must never leave a discoverable provider pointing at a
	// file with weaker-than-intended replacement protections.
	if out, aclErr := exec.Command("icacls", wardenCredentialProviderDir,
		"/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)(F)", "Administrators:(OI)(CI)(RX)").CombinedOutput(); aclErr != nil {
		return fmt.Errorf("protect Credential Provider files: %w: %s", aclErr, string(out))
	}

	// Register COM first and the Credential Provider discovery key last. This
	// makes partial failures invisible to LogonUI instead of showing a broken
	// sign-in tile.
	comPath := `SOFTWARE\Classes\CLSID\` + wardenCredentialProviderCLSID
	comKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, comPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("create provider COM registration: %w", err)
	}
	_ = comKey.SetStringValue("", "Warden Credential Provider")
	comKey.Close()
	inproc, _, err := registry.CreateKey(registry.LOCAL_MACHINE, comPath+`\InprocServer32`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	providerPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\` + wardenCredentialProviderCLSID
	providerKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, providerPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("create Credential Provider registration: %w", err)
	}
	if err := providerKey.SetStringValue("", "Warden Credential Provider"); err != nil {
		providerKey.Close()
		return err
	}
	providerKey.Close()
	if err := inproc.SetStringValue("", target); err == nil {
		err = inproc.SetStringValue("ThreadingModel", "Apartment")
	}
	inproc.Close()
	if err != nil {
		return err
	}

	entries, _ := os.ReadDir(wardenCredentialProviderDir)
	for _, entry := range entries {
		path := filepath.Join(wardenCredentialProviderDir, entry.Name())
		if !entry.IsDir() && !strings.EqualFold(path, target) &&
			strings.HasPrefix(strings.ToLower(entry.Name()), "wardencredentialprovider-") &&
			strings.HasSuffix(strings.ToLower(entry.Name()), ".dll") {
			_ = os.Remove(path)
		}
	}
	return nil
}

// credentialProviderInstalled is deliberately stricter than checking only
// the Credential Providers registry key. A stale key or a COM registration
// redirected to another DLL must not advertise Warden sign-in as ready.
func credentialProviderInstalled() bool {
	providerKey := `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\` + wardenCredentialProviderCLSID
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, providerKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	key.Close()

	comKey := `SOFTWARE\Classes\CLSID\` + wardenCredentialProviderCLSID + `\InprocServer32`
	key, err = registry.OpenKey(registry.LOCAL_MACHINE, comKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	dllPath, _, err := key.GetStringValue("")
	key.Close()
	if err != nil {
		return false
	}
	cleanPath := filepath.Clean(dllPath)
	if !strings.EqualFold(filepath.Dir(cleanPath), filepath.Clean(wardenCredentialProviderDir)) {
		return false
	}
	name := strings.ToLower(filepath.Base(cleanPath))
	if !strings.HasPrefix(name, "wardencredentialprovider-") || !strings.HasSuffix(name, ".dll") {
		return false
	}
	info, err := os.Stat(cleanPath)
	if err != nil || info.IsDir() {
		return false
	}
	actual, err := fileSHA256(cleanPath)
	if err != nil || !strings.HasSuffix(name, actual[:16]+".dll") {
		return false
	}
	expected := strings.ToLower(strings.TrimSpace(buildCredentialProviderSHA256))
	return expected == "" || strings.EqualFold(actual, expected)
}
