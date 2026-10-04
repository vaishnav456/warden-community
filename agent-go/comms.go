package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	apiKey     string
	httpClient *http.Client
	clientMu   sync.Mutex

	pinnedFPs    map[string]struct{}
	pinnedFPMu   sync.Mutex
	tlsTrustMode = "strict_leaf"

	serverClockMu     sync.RWMutex
	serverClockOffset time.Duration
	serverClockKnown  bool
)

func recordServerClock(dateHeader string, requestStarted time.Time) {
	serverTime, err := http.ParseTime(dateHeader)
	if err != nil {
		return
	}
	// Estimate the local time corresponding to the server's second-resolution
	// Date header at the middle of the request. The TLS-pinned response makes
	// this a stronger reference than a VM's occasionally stale wall clock.
	localMidpoint := requestStarted.Add(time.Since(requestStarted) / 2)
	offset := serverTime.Sub(localMidpoint)
	if offset < -24*time.Hour || offset > 24*time.Hour {
		return
	}
	serverClockMu.Lock()
	serverClockOffset, serverClockKnown = offset, true
	serverClockMu.Unlock()
}

func trustedCommandUnix() int64 {
	serverClockMu.RLock()
	offset, known := serverClockOffset, serverClockKnown
	serverClockMu.RUnlock()
	if !known {
		return time.Now().Unix()
	}
	return time.Now().Add(offset).Unix()
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return fmt.Errorf("HTTP redirects are not allowed for Warden agent requests")
}

func normalizeFingerprint(value string) (string, error) {
	fp := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
	if len(fp) != 64 {
		return "", fmt.Errorf("a SHA-256 TLS certificate fingerprint is required")
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return "", fmt.Errorf("invalid TLS certificate fingerprint: %w", err)
	}
	return fp, nil
}

func normalizeTLSTrustMode(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "webpki") {
		return "webpki"
	}
	return "strict_leaf"
}

func initComms(key string, certFingerprints []string, trustMode string) error {
	clientMu.Lock()
	defer clientMu.Unlock()
	apiKey = key
	pins := make(map[string]struct{}, len(certFingerprints))
	for _, value := range certFingerprints {
		fp, err := normalizeFingerprint(value)
		if err != nil {
			return err
		}
		pins[fp] = struct{}{}
	}
	trustMode = normalizeTLSTrustMode(trustMode)
	if trustMode != "webpki" && len(pins) == 0 {
		return fmt.Errorf("at least one TLS certificate fingerprint is required")
	}
	pinnedFPMu.Lock()
	pinnedFPs = pins
	pinnedFPMu.Unlock()
	tlsTrustMode = trustMode
	httpClient = buildPinningClient()
	return nil
}

func replacePinnedFingerprints(values []string) error {
	pins := make(map[string]struct{}, len(values))
	for _, value := range values {
		fp, err := normalizeFingerprint(value)
		if err != nil {
			return err
		}
		pins[fp] = struct{}{}
	}
	if len(pins) == 0 || len(pins) > 3 {
		return fmt.Errorf("TLS pin set must contain between 1 and 3 fingerprints")
	}
	pinnedFPMu.Lock()
	pinnedFPs = pins
	pinnedFPMu.Unlock()
	return nil
}

func currentPinnedFingerprints() map[string]struct{} {
	pinnedFPMu.Lock()
	defer pinnedFPMu.Unlock()
	result := make(map[string]struct{}, len(pinnedFPs))
	for fp := range pinnedFPs {
		result[fp] = struct{}{}
	}
	return result
}

// buildPinningClient pins the server's TLS certificate by SHA-256
// fingerprint. Go's tls.Config always runs full certificate-chain and hostname
// verification before calling VerifyPeerCertificate, unless
// InsecureSkipVerify is set — it isn't, here — so a fingerprint mismatch
// means "a different, but still independently validated, certificate":
// e.g. the server sits behind a CDN/tunnel (Cloudflare Tunnel, etc.) whose
// edge certificate is reissued on its own schedule, not something the
// origin controls. A mismatch must fail closed: silently replacing the trust
// anchor with any other CA-valid certificate defeats pinning. Operators must
// deploy an overlapping pin/update before rotating the public certificate.
func buildPinningClient() *http.Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCert, ok, err := loadClientCertificate(); err != nil {
		logWarn("Could not load mTLS client certificate: %v", err)
	} else if ok {
		tlsCfg.Certificates = []tls.Certificate{clientCert}
		logInfo("mTLS client certificate loaded for outgoing connections.")
	}
	if tlsTrustMode != "webpki" {
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server supplied no TLS leaf certificate")
			}
			h := sha256.Sum256(rawCerts[0])
			actualFP := hex.EncodeToString(h[:])

			pinnedFPMu.Lock()
			_, trusted := pinnedFPs[actualFP]
			pinnedFPMu.Unlock()
			if !trusted {
				return fmt.Errorf("TLS certificate fingerprint mismatch (got %s)", actualFP)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:       time.Duration(heartbeatTimeoutSec) * time.Second,
		CheckRedirect: rejectRedirect,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
}

func reloadClientCertificate() {
	clientMu.Lock()
	httpClient = buildPinningClient()
	clientMu.Unlock()
}

func apiPost(path string, body map[string]interface{}, auth bool, timeoutSec int) (map[string]interface{}, error) {
	raw, err := apiPostRaw(path, body, auth, timeoutSec)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var result map[string]interface{}
	if err := dec.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

func apiPostRaw(path string, body map[string]interface{}, auth bool, timeoutSec int) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var heartbeatReply heartbeatReplyKey
	encryptedHeartbeat := path == heartbeatPath && auth && heartbeatEncryptionRequired()
	if encryptedHeartbeat {
		session, negotiationErr := heartbeatSession()
		if negotiationErr != nil {
			return nil, negotiationErr
		}
		data, heartbeatReply, err = sealHeartbeat(body, session, getConfig().EndpointID, apiKey)
		if err != nil {
			return nil, err
		}
		data, err = signHeartbeatDeviceProof(data, heartbeatReply.context)
		if err != nil {
			return nil, err
		}
	}

	url := serverURL() + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if encryptedHeartbeat {
		req.Header.Set("X-Warden-Heartbeat-Encryption", "1")
	}
	if auth {
		req.Header.Set("X-Agent-Key", apiKey)
		if err := addDeviceRequestProof(req, data); err != nil {
			return nil, err
		}
	}

	clientMu.Lock()
	client := httpClient
	clientMu.Unlock()

	if client == nil && auth {
		return nil, fmt.Errorf("comms not initialized — call initComms first")
	}
	if client == nil {
		client = &http.Client{Timeout: time.Duration(timeoutSec) * time.Second, CheckRedirect: rejectRedirect}
	}

	if timeoutSec > 0 {
		client2 := *client
		client2.Timeout = time.Duration(timeoutSec) * time.Second
		client = &client2
	}

	requestStarted := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	recordServerClock(resp.Header.Get("Date"), requestStarted)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("unexpected HTTP redirect %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if encryptedHeartbeat {
		raw, err = openHeartbeatReply(raw, heartbeatReply, resp.StatusCode)
		if err != nil {
			invalidateHeartbeatSession()
			return nil, err
		}
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

func apiPostAuth(path string, body map[string]interface{}) (map[string]interface{}, error) {
	return apiPost(path, body, true, heartbeatTimeoutSec)
}

func apiPostNoAuth(path string, body map[string]interface{}) (map[string]interface{}, error) {
	return apiPost(path, body, false, 30)
}

// apiPostPinned is used for the one pre-authenticated call that needs TLS
// pinning without an API key: enrollment (see doEnroll in agent.go).
// apiPostNoAuth/apiPost fall back to a bare *http.Client with only standard
// CA-chain/hostname verification when httpClient hasn't been initialized
// yet (always true pre-enrollment) — sufficient against a random attacker,
// but not against a TLS-terminating relay holding any CA-trusted
// certificate (a compromised/coerced CA, a corporate MITM proxy with an
// installed root, etc.) that transparently forwards to the real server:
// the enrollment response (including the freshly issued API key) would
// pass the later Ed25519-pubkey check unmodified since it's genuinely the
// real server's response, while the relay still observed the API key in
// transit. Pinned strictly (no TOFU accept-on-mismatch, unlike
// buildPinningClient's post-enrollment behavior) since the fingerprint
// here is a build-provisioned pin, not something expected to rotate
// between build time and first enrollment.
func apiPostPinned(path string, body map[string]interface{}, certFingerprint string, timeoutSec int) (map[string]interface{}, error) {
	expected := strings.ToLower(strings.ReplaceAll(certFingerprint, ":", ""))
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("server supplied no TLS leaf certificate")
		}
		h := sha256.Sum256(rawCerts[0])
		actualFP := hex.EncodeToString(h[:])
		if actualFP != expected {
			return fmt.Errorf("TLS certificate fingerprint mismatch during enrollment (expected %s, got %s)", expected, actualFP)
		}
		return nil
	}
	client := &http.Client{
		Timeout:       time.Duration(timeoutSec) * time.Second,
		Transport:     &http.Transport{TLSClientConfig: tlsCfg},
		CheckRedirect: rejectRedirect,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", serverURL()+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("unexpected HTTP redirect %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if len(raw) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var result map[string]interface{}
	if err := dec.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// apiPostEnrollment uses normal WebPKI verification for CDN-fronted servers,
// where the valid leaf certificate can differ by edge or rotate without the
// origin operator controlling it. The enrollment response is independently
// authenticated with the build-pinned Ed25519 key and bound to a fresh nonce.
func apiPostEnrollment(path string, body map[string]interface{}, certFingerprint, trustMode string, timeoutSec int) (map[string]interface{}, error) {
	if normalizeTLSTrustMode(trustMode) != "webpki" {
		return apiPostPinned(path, body, certFingerprint, timeoutSec)
	}
	return apiPost(path, body, false, timeoutSec)
}

func reportJobResult(jobID, status string, exitCode int, logOutput, errorMsg string) error {
	body := map[string]interface{}{
		"job_id":     jobID,
		"status":     status,
		"exit_code":  exitCode,
		"log_output": logOutput,
		"error_msg":  errorMsg,
	}
	if _, err := apiPostAuth("/api/agent/job-result", body); err != nil {
		logWarn("job-result POST failed for %s: %v", jobID, err)
		return err
	}
	return nil
}

func appendJobLog(jobID, lines string) {
	body := map[string]interface{}{"job_id": jobID, "lines": lines}
	if _, err := apiPostAuth("/api/agent/log-append", body); err != nil {
		logWarn("log-append POST failed: %v", err)
	}
}
