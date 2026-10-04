package moduletrust

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Stage downloads one approved blob into a pre-created, private directory.
// The caller must protect that directory against other writers (SYSTEM-only
// ACLs on Windows), verify Authenticode and persist anti-rollback state before
// activation. Stage never executes, activates or grants a module permission.
// authorize sets endpoint authentication/proof headers without exposing them
// to the module. Redirects and proxy environment variables are not honored.
func (a *Approved) Stage(ctx context.Context, directory string, authorize func(*http.Request) error) (string, error) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		DisableCompression:    true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return a.stage(ctx, directory, authorize, client, time.Now)
}

// StageWithClient preserves the Core's pinned TLS/device-certificate transport.
// It never adopts the supplied client's redirects or unbounded timeout.
func (a *Approved) StageWithClient(ctx context.Context, directory string, authorize func(*http.Request) error, pinned *http.Client, now func() time.Time) (string, error) {
	if pinned == nil || pinned.Transport == nil || now == nil {
		return "", errors.New("module transport unavailable")
	}
	client := *pinned
	client.Timeout = 60 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return a.stage(ctx, directory, authorize, &client, now)
}

func (a *Approved) stage(ctx context.Context, directory string, authorize func(*http.Request) error, client *http.Client, now func() time.Time) (path string, err error) {
	if a == nil || a.grant.ExpiresAt <= now().Unix() || authorize == nil {
		return "", errors.New("module grant unavailable or expired")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("module staging directory unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.grant.DownloadURL, nil)
	if err != nil {
		return "", errors.New("invalid module request")
	}
	req.Header.Set("Accept-Encoding", "identity")
	if err := authorize(req); err != nil {
		return "", errors.New("module request authentication failed")
	}
	// Authentication hooks may set headers only, never change the signed target.
	if req.Method != http.MethodGet || req.URL == nil || req.URL.String() != a.grant.DownloadURL || req.Body != nil || req.Host != req.URL.Host {
		return "", errors.New("module authentication changed request target")
	}
	response, err := client.Do(req)
	if err != nil {
		return "", errors.New("module download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.ContentLength >= 0 && response.ContentLength != a.grant.SizeBytes) ||
		(response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return "", errors.New("module download response rejected")
	}
	file, err := os.CreateTemp(directory, ".warden-module-*.pending")
	if err != nil {
		return "", errors.New("module staging failed")
	}
	path = file.Name()
	stagedPath := path
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(stagedPath)
			path = ""
		}
	}()
	// Limit includes one extra byte so oversized/chunked responses cannot hide
	// trailing content. A .pending file is never eligible for launch.
	if _, err = io.Copy(file, io.LimitReader(response.Body, a.grant.SizeBytes+1)); err != nil {
		return "", errors.New("module download interrupted")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return "", errors.New("module staging failed")
	}
	if err = a.VerifyPackage(file); err != nil {
		return "", err
	}
	if ctx.Err() != nil || a.grant.ExpiresAt <= now().Unix() {
		return "", errors.New("module grant expired during download")
	}
	if err = file.Sync(); err != nil {
		return "", errors.New("module staging flush failed")
	}
	if err = file.Close(); err != nil {
		return "", errors.New("module staging close failed")
	}
	complete = true
	return path, nil
}
