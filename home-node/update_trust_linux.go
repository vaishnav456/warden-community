//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const linuxUpdateTrustPath = "/etc/warden-home-update/identity.json"

type updateTrustIdentity struct {
	NodeID          string `json:"node_id"`
	ServerPublicKey string `json:"server_public_key"`
}

func checkRootOwnedUpdatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || info.Mode().Perm()&0022 != 0 ||
		info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory ||
		(!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("update trust must be root-owned and not writable by the Home service: %s", path)
	}
	return nil
}

func readUpdateTrustIdentity(path string) (updateTrustIdentity, error) {
	var identity updateTrustIdentity
	if err := checkRootOwnedUpdatePath(filepath.Dir(path), true); err != nil {
		return identity, err
	}
	if err := checkRootOwnedUpdatePath(path, false); err != nil {
		return identity, err
	}
	// The checked parent is not service-writable, preventing path replacement.
	handle, err := os.Open(path)
	if err != nil {
		return identity, err
	}
	defer handle.Close()
	err = json.NewDecoder(io.LimitReader(handle, 4096)).Decode(&identity)
	key, decodeErr := base64.StdEncoding.DecodeString(identity.ServerPublicKey)
	if err != nil || decodeErr != nil || len(key) != ed25519.PublicKeySize || identity.NodeID == "" {
		return identity, fmt.Errorf("invalid root-owned Home update identity")
	}
	return identity, nil
}

func initializeManagedUpdateTrust(installed config) error {
	directory := filepath.Dir(linuxUpdateTrustPath)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err := checkRootOwnedUpdatePath(directory, true); err != nil {
		return err
	}
	if _, err := os.Lstat(linuxUpdateTrustPath); err == nil {
		identity, err := readUpdateTrustIdentity(linuxUpdateTrustPath)
		if err != nil {
			return err
		}
		if identity.NodeID != installed.NodeID || identity.ServerPublicKey != installed.ServerPublicKey {
			return fmt.Errorf("Home update identity differs from existing root-owned pin; explicit administrator reconfiguration required")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(installed.ServerPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || installed.NodeID == "" {
		return fmt.Errorf("invalid Home update identity")
	}
	raw, err := json.Marshal(updateTrustIdentity{installed.NodeID, installed.ServerPublicKey})
	if err != nil {
		return err
	}
	handle, err := os.OpenFile(linuxUpdateTrustPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := handle.Write(raw)
	closeErr := handle.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func requireManagedUpdateTrust(path string) error {
	if _, err := readUpdateTrustIdentity(path); err != nil {
		return fmt.Errorf("before upgrading, run trust-updates -config <administrator-verified-config> as root to configure the protected update identity: %w", err)
	}
	return nil
}

func loadManagedUpdateConfig(_ string) error {
	// Never call loadConfig here: service-owned certificate paths and keys
	// must not drive network requests or filesystem writes as root.
	identity, err := readUpdateTrustIdentity(linuxUpdateTrustPath)
	if err != nil {
		return fmt.Errorf("trusted Home update identity unavailable; administrator must configure the root-owned pin: %w", err)
	}
	key, _ := base64.StdEncoding.DecodeString(identity.ServerPublicKey)
	cfg.NodeID = identity.NodeID
	pub = ed25519.PublicKey(key)
	return nil
}

func configureManagedUpdateTrust(path string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("trust-updates must run as root")
	}
	// Explicit administrator action only. Never bootstrap trust automatically
	// from service-writable configuration in the update path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var installed config
	if err := json.Unmarshal(raw, &installed); err != nil {
		return err
	}
	return initializeManagedUpdateTrust(installed)
}
