package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type config struct {
	BackupRoot           string `json:"backup_root"`
	BackupMaxBytes       int64  `json:"backup_max_bytes"`
	BackupIntervalHours  int    `json:"backup_interval_hours"`
	PackageCacheMaxBytes int64  `json:"package_cache_max_bytes"`
	NodeID               string `json:"node_id"`
	NodeKey              string `json:"node_key"`
	WardenURL            string `json:"warden_url"`
	ServerPublicKey      string `json:"server_public_key"`
	Listen               string `json:"listen"`
	Root                 string `json:"root"`
	TLSCert              string `json:"tls_cert"`
	TLSKey               string `json:"tls_key"`
	ClientCA             string `json:"client_ca"`
	ClientCert           string `json:"client_cert"`
	ClientKey            string `json:"client_key"`
	EncryptionKey        string `json:"encryption_key"`
	PublicMode           bool   `json:"public_mode"`
	Replication          bool   `json:"replication"`
	StorageClusterID     string `json:"storage_cluster_id"`
}

func decodeB64(s string) ([]byte, error) {
	if v, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return v, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func loadConfig(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if err := validateHomeServerURL(cfg.WardenURL); err != nil {
		return err
	}
	configPathInUse = path
	if cfg.NodeID != "" && cfg.NodeKey != "" && cfg.WardenURL != "" {
		if err := ensureNodeCertificate(path, 0); err != nil {
			return fmt.Errorf("bootstrap Warden Home certificate: %w", err)
		}
	}
	if cfg.NodeID == "" || cfg.NodeKey == "" || cfg.WardenURL == "" || cfg.ServerPublicKey == "" || cfg.Root == "" || cfg.TLSCert == "" || cfg.TLSKey == "" || cfg.EncryptionKey == "" {
		return errors.New("missing required config")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":9443"
	}
	rawPub, err := decodeB64(cfg.ServerPublicKey)
	if err != nil || len(rawPub) != ed25519.PublicKeySize {
		return errors.New("invalid server public key")
	}
	pub = ed25519.PublicKey(rawPub)
	key, err := decodeB64(cfg.EncryptionKey)
	if err != nil || len(key) != 32 {
		return errors.New("encryption_key must be base64 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}
	keyDigest := sha256.Sum256(key)
	encryptionKeyID = hex.EncodeToString(keyDigest[:])
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		peerClientCert, err = tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return err
		}
		peerCertLoaded = true
	}
	if cfg.PublicMode && (cfg.ClientCA == "" || !peerCertLoaded) {
		return errors.New("public_mode requires client_ca and client certificate")
	}
	if err := os.MkdirAll(cfg.Root, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(cfg.Root, ".warden-restore-incomplete")); err == nil {
		return errors.New("refusing incomplete restored Home store")
	} else if !os.IsNotExist(err) {
		return err
	}
	return loadReplicationState()
}
