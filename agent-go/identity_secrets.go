package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const identitySecretsPath = `C:\ProgramData\WardenAgent\identity-secrets.bin`

type managedIdentitySecret struct {
	Password string `json:"password"`
}

type managedIdentitySecrets map[string]managedIdentitySecret

var identitySecretsMu sync.Mutex

func identitySecretKey(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func loadManagedIdentitySecrets() (managedIdentitySecrets, error) {
	data, err := os.ReadFile(identitySecretsPath)
	if os.IsNotExist(err) {
		return managedIdentitySecrets{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read managed identity secrets: %w", err)
	}
	plain, err := decryptDPAPI(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt managed identity secrets: %w", err)
	}
	defer clearBytes(plain)
	secrets := managedIdentitySecrets{}
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return nil, fmt.Errorf("decode managed identity secrets: %w", err)
	}
	return secrets, nil
}

func saveManagedIdentitySecrets(secrets managedIdentitySecrets) error {
	ensureDirs()
	plain, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	defer clearBytes(plain)
	ciphertext, err := encryptDPAPI(plain, "Warden managed identity credentials")
	if err != nil {
		return fmt.Errorf("encrypt managed identity secrets: %w", err)
	}
	tmp := identitySecretsPath + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0600); err != nil {
		return fmt.Errorf("write managed identity secrets: %w", err)
	}
	out, err := exec.Command(
		"icacls", tmp, "/inheritance:r", "/grant:r", "SYSTEM:(F)",
	).CombinedOutput()
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("restrict managed identity secret DACL: %w: %s", err, string(out))
	}
	if err := os.Remove(identitySecretsPath); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, identitySecretsPath); err != nil {
		return fmt.Errorf("activate managed identity secrets: %w", err)
	}
	return nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func newManagedIdentityPassword() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	// Raw URL encoding avoids quotes, whitespace and shell metacharacters;
	// the fixed suffix guarantees all Windows password-complexity classes.
	return base64.RawURLEncoding.EncodeToString(random) + "!Aa1", nil
}

func managedIdentityPassword(username string) (string, bool, error) {
	identitySecretsMu.Lock()
	defer identitySecretsMu.Unlock()
	secrets, err := loadManagedIdentitySecrets()
	if err != nil {
		return "", false, err
	}
	secret, ok := secrets[identitySecretKey(username)]
	if !ok || secret.Password == "" {
		return "", false, nil
	}
	return secret.Password, true, nil
}

func putManagedIdentityPassword(username, password string) error {
	identitySecretsMu.Lock()
	defer identitySecretsMu.Unlock()
	secrets, err := loadManagedIdentitySecrets()
	if err != nil {
		return err
	}
	secrets[identitySecretKey(username)] = managedIdentitySecret{Password: password}
	return saveManagedIdentitySecrets(secrets)
}

func removeManagedIdentityPassword(username string) error {
	identitySecretsMu.Lock()
	defer identitySecretsMu.Unlock()
	secrets, err := loadManagedIdentitySecrets()
	if err != nil {
		return err
	}
	key := identitySecretKey(username)
	if _, ok := secrets[key]; !ok {
		return nil
	}
	delete(secrets, key)
	return saveManagedIdentitySecrets(secrets)
}
