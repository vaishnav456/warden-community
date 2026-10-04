package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
	if err := addDeviceRequestProof(req, nil); err != nil {
		return err
	}

	clientMu.Lock()
	client := httpClient
	clientMu.Unlock()
	if client == nil {
		return fmt.Errorf("comms not initialized — call initComms first")
	}
	client2 := *client
	if err = refreshBranchTraffic(); err != nil {
		return fmt.Errorf("cannot enforce branch traffic policy: %w", err)
	}
	client2.Timeout = 30 * time.Minute
	client2.CheckRedirect = rejectRedirect
	client2.Transport = branchTrafficTransport{base: client.Transport}
	resp, cacheErr := packageCacheResponse(validatedURL, sha256hex)
	if cacheErr != nil {
		logWarn("Branch package cache unavailable; using verified server download")
	}
	if resp == nil {
		resp, err = client2.Do(req)
	}
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
	if strings.TrimSpace(productName) == "" {
		return 1, "", fmt.Errorf("missing product_name")
	}
	return runAppUninstall(productName)
}
