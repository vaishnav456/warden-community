package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pendingCredentialsPath = `C:\ProgramData\WardenAgent\credentials.pending`

var (
	crypt32            = windows.NewLazySystemDLL("Crypt32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func blobFromBytes(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (b *dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	return unsafe.Slice(b.pbData, b.cbData)
}

func encryptDPAPI(plaintext []byte, description string) ([]byte, error) {
	desc, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, err
	}
	in := blobFromBytes(plaintext)
	var out dataBlob
	r, _, e := procCryptProtect.Call(
		uintptr(unsafe.Pointer(in)),
		uintptr(unsafe.Pointer(desc)),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", e)
	}
	result := make([]byte, out.cbData)
	copy(result, out.bytes())
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return result, nil
}

func decryptDPAPI(ciphertext []byte) ([]byte, error) {
	in := blobFromBytes(ciphertext)
	var out dataBlob
	r, _, e := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", e)
	}
	result := make([]byte, out.cbData)
	copy(result, out.bytes())
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return result, nil
}

func saveAPIKey(apiKey string) error {
	enc, err := encryptDPAPI([]byte(apiKey), "WardenAgent API Key")
	if err != nil {
		return fmt.Errorf("DPAPI encrypt: %w", err)
	}
	if err := os.WriteFile(credentialsPath, enc, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	out, err := exec.Command(
		"icacls", credentialsPath, "/inheritance:r", "/grant:r",
		"SYSTEM:(F)", "Administrators:(F)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("restrict credential DACL: %w: %s", err, string(out))
	}
	return nil
}

func writeProtectedCredential(path, apiKey string) error {
	enc, err := encryptDPAPI([]byte(apiKey), "WardenAgent API Key")
	if err != nil {
		return fmt.Errorf("DPAPI encrypt: %w", err)
	}
	if err := os.WriteFile(path, enc, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	out, err := exec.Command(
		"icacls", path, "/inheritance:r", "/grant:r",
		"SYSTEM:(F)", "Administrators:(F)",
	).CombinedOutput()
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("restrict credential DACL: %w: %s", err, string(out))
	}
	return nil
}

// stagePendingEnrollment persists both halves of enrollment before replacing
// either live file. A service crash at any later point can finish locally
// without consuming another enrollment-token use or creating a ghost endpoint.
func stagePendingEnrollment(c AgentConfig, apiKey string) error {
	ensureDirs()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(pendingEnrollPath, data, 0600); err != nil {
		return err
	}
	if err := writeProtectedCredential(pendingCredentialsPath, apiKey); err != nil {
		_ = os.Remove(pendingEnrollPath)
		return err
	}
	return nil
}

func recoverPendingEnrollment() error {
	data, err := os.ReadFile(pendingEnrollPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var finalConfig AgentConfig
	if err := json.Unmarshal(data, &finalConfig); err != nil {
		return fmt.Errorf("decode pending enrollment: %w", err)
	}
	if finalConfig.EndpointID == "" || finalConfig.ServerEd25519Pubkey == "" {
		return fmt.Errorf("pending enrollment is incomplete")
	}
	if _, err := os.Stat(pendingCredentialsPath); err == nil {
		_ = os.Remove(credentialsPath)
		if err := os.Rename(pendingCredentialsPath, credentialsPath); err != nil {
			return fmt.Errorf("activate pending credentials: %w", err)
		}
	} else if _, activeErr := os.Stat(credentialsPath); activeErr != nil {
		// The service may have stopped after the server responded but before
		// the DPAPI blob reached disk. Discard only the incomplete local
		// transaction: the bootstrap token/config remains available and the
		// server's bounded idempotent-enrollment path will rotate the lost key.
		if removeErr := os.Remove(pendingEnrollPath); removeErr != nil {
			return fmt.Errorf("discard incomplete pending enrollment: %w", removeErr)
		}
		return nil
	}
	if err := saveConfig(finalConfig); err != nil {
		// The active credential remains safe. Leave the pending config so the
		// next service start retries only this final local step.
		return err
	}
	return os.Remove(pendingEnrollPath)
}

func loadAPIKey() (string, error) {
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		return "", fmt.Errorf("read credentials: %w", err)
	}
	plain, err := decryptDPAPI(data)
	if err != nil {
		return "", fmt.Errorf("DPAPI decrypt: %w", err)
	}
	return string(plain), nil
}
