package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const homeNodeVersion = "1.1.0"

type managedUpdate struct {
	NodeID      string `json:"node_id"`
	Version     string `json:"version"`
	Platform    string `json:"platform"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	Signature   string `json:"signature"`
}

var managedUpdateRunning atomic.Bool

func compareVersions(left, right string) (int, error) {
	parse := func(value string) ([3]int, error) {
		var parsed [3]int
		parts := strings.Split(strings.TrimSpace(value), ".")
		if len(parts) != 3 {
			return parsed, fmt.Errorf("version %q must be major.minor.patch", value)
		}
		for index, part := range parts {
			number, err := strconv.Atoi(part)
			if err != nil || number < 0 {
				return parsed, fmt.Errorf("version %q contains a non-numeric component", value)
			}
			parsed[index] = number
		}
		return parsed, nil
	}
	a, err := parse(left)
	if err != nil {
		return 0, err
	}
	b, err := parse(right)
	if err != nil {
		return 0, err
	}
	for index := range a {
		if a[index] < b[index] {
			return -1, nil
		}
		if a[index] > b[index] {
			return 1, nil
		}
	}
	return 0, nil
}

func managedUpdateCanonical(update managedUpdate) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"download_url": update.DownloadURL,
		"expires_at":   update.ExpiresAt,
		"issued_at":    update.IssuedAt,
		"node_id":      update.NodeID,
		"platform":     update.Platform,
		"sha256":       update.SHA256,
		"version":      update.Version,
	})
}

func verifyManagedUpdate(update managedUpdate, allowCurrentVersion bool) error {
	if update.NodeID != cfg.NodeID {
		return errors.New("managed update targets a different node")
	}
	if update.Platform != runtime.GOOS+"-"+runtime.GOARCH {
		return errors.New("managed update targets a different platform")
	}
	if len(update.SHA256) != 64 {
		return errors.New("managed update has an invalid SHA-256")
	}
	if _, err := hex.DecodeString(update.SHA256); err != nil {
		return errors.New("managed update has an invalid SHA-256")
	}
	now := time.Now().Unix()
	if update.ExpiresAt < now || update.IssuedAt > now+300 || update.ExpiresAt-update.IssuedAt > 48*60*60 {
		return errors.New("managed update manifest is expired or has invalid timing")
	}
	if comparison, err := compareVersions(update.Version, homeNodeVersion); err != nil {
		return err
	} else if comparison < 0 || (comparison == 0 && !allowCurrentVersion) {
		return errors.New("managed update is not newer than the installed version")
	}
	signature, err := base64.StdEncoding.DecodeString(update.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("managed update signature is invalid")
	}
	message, err := managedUpdateCanonical(update)
	if err != nil || !ed25519.Verify(pub, message, signature) {
		return errors.New("managed update signature verification failed")
	}
	return nil
}

func downloadManagedUpdate(update managedUpdate, destination string) error {
	request, err := http.NewRequest(http.MethodGet, update.DownloadURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("X-Warden-Home-Key", cfg.NodeKey)
	response, err := (&http.Client{Timeout: 15 * time.Minute}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Warden returned HTTP %d", response.StatusCode)
	}
	target, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(target, digest), io.LimitReader(response.Body, 128*1024*1024+1))
	closeErr := target.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written <= 0 || written > 128*1024*1024 {
		return errors.New("managed update artifact has an invalid size")
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), update.SHA256) {
		return errors.New("managed update SHA-256 verification failed")
	}
	return nil
}

func stageManagedUpdate(update managedUpdate) error {
	if err := verifyManagedUpdate(update, false); err != nil {
		return err
	}
	directory := managedUpdateDirectory()
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	staged := filepath.Join(directory, "warden-home-node.new")
	temporary := staged + ".tmp"
	manifest := filepath.Join(directory, "update.json")
	manifestTemporary := manifest + ".tmp"
	_ = os.Remove(temporary)
	_ = os.Remove(manifestTemporary)
	if err := downloadManagedUpdate(update, temporary); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, staged); err != nil {
		return err
	}
	raw, err := json.Marshal(update)
	if err != nil {
		return err
	}
	if err = os.WriteFile(manifestTemporary, append(raw, '\n'), 0600); err != nil {
		return err
	}
	if err = os.Rename(manifestTemporary, manifest); err != nil {
		return err
	}
	return scheduleManagedUpdate(manifest)
}

func considerManagedUpdate(update *managedUpdate) {
	if update == nil {
		return
	}
	if comparison, err := compareVersions(update.Version, homeNodeVersion); err != nil || comparison <= 0 {
		return
	}
	if !managedUpdateRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		if err := stageManagedUpdate(*update); err != nil {
			log.Printf("Managed Home Node update deferred: %v", err)
			managedUpdateRunning.Store(false)
			return
		}
		log.Printf("Managed Home Node update %s verified and scheduled", update.Version)
	}()
}

func applyManagedUpdateManifest(manifest string) error {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	var update managedUpdate
	if err = json.Unmarshal(raw, &update); err != nil {
		return err
	}
	if err = verifyManagedUpdate(update, true); err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(manifest), "warden-home-node.new")
	handle, err := os.Open(staged)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, io.LimitReader(handle, 128*1024*1024+1))
	handle.Close()
	if copyErr != nil || !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), update.SHA256) {
		return errors.New("staged managed update failed SHA-256 verification")
	}
	defer os.Remove(manifest)
	defer os.Remove(staged)
	defer os.Remove(filepath.Join(filepath.Dir(manifest), "ready"))
	return installManagedUpdate(staged)
}

func copyFileExact(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err = output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}
