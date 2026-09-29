package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"image/jpeg"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	cpuPkg "github.com/shirou/gopsutil/v3/cpu"
	diskPkg "github.com/shirou/gopsutil/v3/disk"
	hostPkg "github.com/shirou/gopsutil/v3/host"
	memPkg "github.com/shirou/gopsutil/v3/mem"
)

const agentVersion = "2.3.4"

var (
	buildServerURL, buildServerEd25519Pubkey, buildCertFingerprint, buildTLSTrustMode string
	dataDir, installDir, configPath, credentialsPath, keyPath, certPath               string
	elevationsPath                                                                    string
	cfg                                                                               Config
	apiKey                                                                            string
	httpClient                                                                        *http.Client
	remoteMu                                                                          sync.Mutex
	configMu                                                                          sync.RWMutex
	clientMu                                                                          sync.RWMutex
	remoteActive                                                                      *remoteSession
	jobIDPattern                                                                      = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)
	usernamePattern                                                                   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
)

const (
	nonceTTLSeconds = 5 * 60
	jobTTLSeconds   = 90 * 24 * 60 * 60
)

type remoteSession struct {
	stop chan struct{}
	done chan struct{}
}

type replayEntry struct {
	CreatedAt int64 `json:"created_at"`
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

type completedJob struct {
	Status      string `json:"status"`
	ExitCode    int    `json:"exit_code"`
	LogOutput   string `json:"log_output"`
	ErrorMsg    string `json:"error_msg"`
	CompletedAt int64  `json:"completed_at"`
}

type replayStore struct {
	Nonces         map[string]replayEntry  `json:"nonces"`
	Jobs           map[string]completedJob `json:"jobs"`
	PendingReports map[string]completedJob `json:"pending_reports,omitempty"`
}

var (
	replayMu    sync.Mutex
	elevationMu sync.Mutex
	replayPath  string
	replays     = replayStore{Nonces: map[string]replayEntry{}, Jobs: map[string]completedJob{}, PendingReports: map[string]completedJob{}}
)

type Config struct {
	ServerURL           string   `json:"server_url"`
	ServerEd25519Pubkey string   `json:"server_ed25519_pubkey"`
	CertFingerprint     string   `json:"cert_fingerprint"`
	CertFingerprints    []string `json:"cert_fingerprints,omitempty"`
	TLSTrustMode        string   `json:"tls_trust_mode,omitempty"`
	InstallationID      string   `json:"installation_id,omitempty"`
	EnrollmentToken     string   `json:"enrollment_token,omitempty"`
	EndpointID          string   `json:"endpoint_id,omitempty"`
	CompanyID           string   `json:"company_id,omitempty"`
	BranchID            string   `json:"branch_id,omitempty"`
}

type Envelope struct {
	JobID     string                 `json:"job_id"`
	Nonce     string                 `json:"nonce"`
	IssuedAt  int64                  `json:"issued_at"`
	ExpiresAt int64                  `json:"expires_at"`
	Operation string                 `json:"operation"`
	Payload   map[string]interface{} `json:"payload"`
}

func initPaths() {
	if runtime.GOOS == "darwin" {
		dataDir = "/Library/Application Support/WardenAgent"
		installDir = "/Library/PrivilegedHelperTools"
	} else {
		dataDir = "/var/lib/warden-agent"
		installDir = "/usr/local/lib/warden-agent"
	}
	configPath = filepath.Join(dataDir, "config.json")
	credentialsPath = filepath.Join(dataDir, "credentials")
	replayPath = filepath.Join(dataDir, "replay-state.json")
	elevationsPath = filepath.Join(dataDir, "elevations.json")
	keyPath = filepath.Join(dataDir, "client-key.pem")
	certPath = filepath.Join(dataDir, "client-cert.pem")
}

func main() {
	initPaths()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			must(installService())
			return
		case "remove":
			must(removeService())
			return
		case "capabilities":
			caps, details := capabilities()
			b, _ := json.MarshalIndent(map[string]interface{}{"capabilities": caps, "details": details}, "", "  ")
			fmt.Println(string(b))
			return
		case "run":
		default:
			fmt.Fprintln(os.Stderr, "usage: warden-agent [install|remove|run|capabilities]")
			os.Exit(2)
		}
	}
	run()
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func run() {
	must(os.MkdirAll(dataDir, 0700))
	must(initReplayStore())
	must(seedConfig())
	must(loadConfig())
	if cfg.EndpointID == "" || readSecret(credentialsPath) == "" {
		token := os.Getenv("WARDEN_ENROLLMENT_TOKEN")
		if token == "" {
			token = cfg.EnrollmentToken
		}
		if token == "" {
			log.Fatal("agent is not enrolled and no enrollment token is configured")
		}
		must(enroll(token))
		must(loadConfig())
	}
	apiKey = readSecret(credentialsPath)
	must(initHTTP())
	pub, err := base64.StdEncoding.DecodeString(cfg.ServerEd25519Pubkey)
	must(err)
	if len(pub) != ed25519.PublicKeySize {
		log.Fatal("invalid server signing key")
	}
	_ = reportSysinfo()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	jobQueue := make(chan json.RawMessage, 1)
	var jobWorkerBusy atomic.Bool
	go func() {
		for raw := range jobQueue {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						log.Printf("recovered panic in job worker: %v", recovered)
					}
				}()
				processJob(raw, ed25519.PublicKey(pub))
			}()
			jobWorkerBusy.Store(false)
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		cleanupReplayStore()
		revokeExpiredElevations()
		flushPendingJobResults()
		capacity := 0
		if !jobWorkerBusy.Load() && len(jobQueue) == 0 {
			capacity = 1
		}
		commands, err := heartbeat(capacity)
		if err != nil {
			log.Printf("heartbeat: %v", err)
		} else {
			for _, raw := range commands {
				jobWorkerBusy.Store(true)
				select {
				case jobQueue <- raw:
				default:
					jobWorkerBusy.Store(false)
					log.Printf("job queue full; command will be retried after its lease expires")
				}
			}
		}
		select {
		case <-ctx.Done():
			stopRemote()
			close(jobQueue)
			return
		case <-ticker.C:
		}
	}
}

func seedConfig() error {
	if _, err := os.Stat(configPath); err == nil {
		return nil
	}
	source := filepath.Join(filepath.Dir(os.Args[0]), "config.json")
	if b, err := os.ReadFile(source); err == nil {
		if err := os.WriteFile(configPath, b, 0600); err != nil {
			return err
		}
		return nil
	}
	if buildServerEd25519Pubkey == "" || (normalizeTLSTrustMode(buildTLSTrustMode) != "webpki" && buildCertFingerprint == "") {
		return errors.New("missing config.json and build pins")
	}
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	c := Config{ServerURL: buildServerURL, ServerEd25519Pubkey: buildServerEd25519Pubkey, CertFingerprint: buildCertFingerprint, CertFingerprints: []string{buildCertFingerprint}, TLSTrustMode: normalizeTLSTrustMode(buildTLSTrustMode), InstallationID: id}
	return writeJSON(configPath, c, 0600)
}

func loadConfig() error {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var loaded Config
	if err = json.Unmarshal(b, &loaded); err != nil {
		return err
	}
	configMu.Lock()
	cfg = loaded
	configMu.Unlock()
	return nil
}
func saveConfig(c Config) error {
	c.EnrollmentToken = ""
	if err := writeJSON(configPath, c, 0600); err != nil {
		return err
	}
	configMu.Lock()
	cfg = c
	configMu.Unlock()
	return nil
}

func configSnapshot() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	c := cfg
	c.CertFingerprints = append([]string(nil), cfg.CertFingerprints...)
	return c
}
func writeJSON(path string, value interface{}, mode os.FileMode) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func readSecret(path string) string { b, _ := os.ReadFile(path); return strings.TrimSpace(string(b)) }
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func initReplayStore() error {
	replayMu.Lock()
	defer replayMu.Unlock()
	b, err := os.ReadFile(replayPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read replay store: %w", err)
	}
	if err = json.Unmarshal(b, &replays); err != nil {
		return fmt.Errorf("decode replay store: %w", err)
	}
	if replays.Nonces == nil {
		replays.Nonces = map[string]replayEntry{}
	}
	if replays.Jobs == nil {
		replays.Jobs = map[string]completedJob{}
	}
	if replays.PendingReports == nil {
		replays.PendingReports = map[string]completedJob{}
	}
	return nil
}

func saveReplayStoreLocked() error {
	b, err := json.Marshal(replays)
	if err != nil {
		return err
	}
	tmp := replayPath + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, replayPath)
}

func checkAndConsumeNonce(nonce string, expiresAt int64) error {
	replayMu.Lock()
	defer replayMu.Unlock()
	if _, exists := replays.Nonces[nonce]; exists {
		return errors.New("replayed command nonce")
	}
	replays.Nonces[nonce] = replayEntry{CreatedAt: time.Now().Unix(), ExpiresAt: expiresAt}
	if err := saveReplayStoreLocked(); err != nil {
		delete(replays.Nonces, nonce)
		return fmt.Errorf("persist command nonce: %w", err)
	}
	return nil
}

func getCompletedJob(jobID string) (completedJob, bool) {
	replayMu.Lock()
	defer replayMu.Unlock()
	result, ok := replays.Jobs[jobID]
	return result, ok
}

func recordCompletedJob(jobID string, result completedJob) error {
	replayMu.Lock()
	defer replayMu.Unlock()
	result.CompletedAt = time.Now().Unix()
	replays.Jobs[jobID] = result
	replays.PendingReports[jobID] = result
	return saveReplayStoreLocked()
}

func queuePendingReport(jobID string, result completedJob) error {
	replayMu.Lock()
	defer replayMu.Unlock()
	replays.PendingReports[jobID] = result
	return saveReplayStoreLocked()
}

func pendingJobReports() map[string]completedJob {
	replayMu.Lock()
	defer replayMu.Unlock()
	out := make(map[string]completedJob, len(replays.PendingReports))
	for jobID, result := range replays.PendingReports {
		out[jobID] = result
	}
	return out
}

func acknowledgeJobReport(jobID string) error {
	replayMu.Lock()
	defer replayMu.Unlock()
	result, exists := replays.PendingReports[jobID]
	if !exists {
		return nil
	}
	delete(replays.PendingReports, jobID)
	if err := saveReplayStoreLocked(); err != nil {
		replays.PendingReports[jobID] = result
		return err
	}
	return nil
}

func reportJobResult(jobID string, result completedJob) error {
	return post("/api/agent/job-result", map[string]interface{}{
		"job_id": jobID, "status": result.Status, "exit_code": result.ExitCode,
		"log_output": result.LogOutput, "error_msg": result.ErrorMsg,
	}, true, nil)
}

func flushPendingJobResults() {
	for jobID, result := range pendingJobReports() {
		if err := reportJobResult(jobID, result); err != nil {
			log.Printf("job result %s: %v", jobID, err)
			continue
		}
		if err := acknowledgeJobReport(jobID); err != nil {
			log.Printf("persist job acknowledgement %s: %v", jobID, err)
		}
	}
}

func cleanupReplayStore() {
	now := time.Now().Unix()
	replayMu.Lock()
	defer replayMu.Unlock()
	changed := false
	for nonce, entry := range replays.Nonces {
		keepUntil := entry.ExpiresAt + 120
		if entry.ExpiresAt == 0 {
			keepUntil = entry.CreatedAt + nonceTTLSeconds
		}
		if keepUntil < now {
			delete(replays.Nonces, nonce)
			changed = true
		}
	}
	for jobID, result := range replays.Jobs {
		if _, pending := replays.PendingReports[jobID]; !pending && result.CompletedAt < now-jobTTLSeconds {
			delete(replays.Jobs, jobID)
			changed = true
		}
	}
	if changed {
		if err := saveReplayStoreLocked(); err != nil {
			log.Printf("replay-store cleanup: %v", err)
		}
	}
}

func loadElevations() map[string]int64 {
	entries := map[string]int64{}
	if b, err := os.ReadFile(elevationsPath); err == nil {
		_ = json.Unmarshal(b, &entries)
	}
	return entries
}

func saveElevations(entries map[string]int64) error {
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	tmp := elevationsPath + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, elevationsPath)
}

func recordElevationExpiry(username string, durationMinutes int64) error {
	if durationMinutes < 1 || durationMinutes > 1440 {
		return errors.New("duration_minutes must be between 1 and 1440")
	}
	elevationMu.Lock()
	defer elevationMu.Unlock()
	entries := loadElevations()
	entries[strings.ToLower(username)] = time.Now().Unix() + durationMinutes*60
	return saveElevations(entries)
}

func removeElevationExpiry(username string) error {
	elevationMu.Lock()
	defer elevationMu.Unlock()
	entries := loadElevations()
	delete(entries, strings.ToLower(username))
	return saveElevations(entries)
}

func elevationRevokeCommand(username string) *exec.Cmd {
	if runtime.GOOS == "darwin" {
		return exec.Command("dseditgroup", "-o", "edit", "-d", username, "-t", "user", "admin")
	}
	group := "sudo"
	if commandText("getent", "group", "sudo") == "" {
		group = "wheel"
	}
	return exec.Command("gpasswd", "-d", username, group)
}

func revokeExpiredElevations() {
	elevationMu.Lock()
	defer elevationMu.Unlock()
	entries := loadElevations()
	now := time.Now().Unix()
	changed := false
	for username, expiresAt := range entries {
		if expiresAt > now {
			continue
		}
		if output, err := elevationRevokeCommand(username).CombinedOutput(); err != nil {
			log.Printf("revoke expired elevation for %s: %v: %s", username, err, output)
			continue
		}
		delete(entries, username)
		changed = true
	}
	if changed {
		if err := saveElevations(entries); err != nil {
			log.Printf("persist elevation cleanup: %v", err)
		}
	}
}

func pins() []string {
	c := configSnapshot()
	if len(c.CertFingerprints) > 0 {
		return c.CertFingerprints
	}
	return []string{c.CertFingerprint}
}
func normalizeTLSTrustMode(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "webpki") {
		return "webpki"
	}
	return "strict_leaf"
}
func tlsConfig(expected []string, trustMode string) (*tls.Config, error) {
	trusted := map[string]bool{}
	if normalizeTLSTrustMode(trustMode) != "webpki" {
		for _, p := range expected {
			p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
			if len(p) != 64 {
				return nil, errors.New("invalid TLS fingerprint")
			}
			trusted[p] = true
		}
	}
	t := &tls.Config{MinVersion: tls.VersionTLS12}
	if normalizeTLSTrustMode(trustMode) != "webpki" {
		t.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("missing TLS certificate")
			}
			h := sha256.Sum256(raw[0])
			if !trusted[hex.EncodeToString(h[:])] {
				return errors.New("TLS certificate fingerprint mismatch")
			}
			return nil
		}
	}
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		t.Certificates = []tls.Certificate{cert}
	}
	return t, nil
}
func initHTTP() error {
	c := configSnapshot()
	t, err := tlsConfig(pins(), c.TLSTrustMode)
	if err != nil {
		return err
	}
	next := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: t}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	clientMu.Lock()
	httpClient = next
	clientMu.Unlock()
	return nil
}
func serverURL() string { return strings.TrimRight(configSnapshot().ServerURL, "/") }
func post(path string, body interface{}, auth bool, out interface{}) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", serverURL()+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth {
		req.Header.Set("X-Agent-Key", apiKey)
	}
	clientMu.RLock()
	client := httpClient
	clientMu.RUnlock()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func enroll(token string) error {
	c := configSnapshot()
	if c.InstallationID == "" {
		id, err := randomHex(16)
		if err != nil {
			return err
		}
		c.InstallationID = id
		if err = writeJSON(configPath, c, 0600); err != nil {
			return err
		}
		configMu.Lock()
		cfg = c
		configMu.Unlock()
	}
	key, csr, err := generateCSR()
	if err != nil {
		return err
	}
	t, err := tlsConfig([]string{c.CertFingerprint}, c.TLSTrustMode)
	if err != nil {
		return err
	}
	clientMu.Lock()
	httpClient = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: t}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	clientMu.Unlock()
	host, _ := os.Hostname()
	info := systemInfo()
	identity := deviceIdentity()
	enrollmentNonce, err := randomHex(32)
	if err != nil {
		return err
	}
	var response map[string]interface{}
	err = post("/enroll", map[string]interface{}{"token": token, "hostname": host, "hardware_id": identity["hardware_id"], "device_identity": identity, "agent_version": agentVersion, "os_info": info, "csr_pem": string(csr), "installation_id": c.InstallationID, "enrollment_nonce": enrollmentNonce}, false, &response)
	if err != nil {
		return err
	}
	serverKey, _ := response["server_ed25519_pubkey"].(string)
	if serverKey != c.ServerEd25519Pubkey {
		return errors.New("server signing key does not match build pin")
	}
	if err = verifyEnrollmentResponse(response, c.ServerEd25519Pubkey, enrollmentNonce); err != nil {
		return fmt.Errorf("verify enrollment response: %w", err)
	}
	secret, _ := response["api_key"].(string)
	if secret == "" {
		return errors.New("enrollment response missing API key")
	}
	if cert, _ := response["client_cert_pem"].(string); cert != "" {
		if err = os.WriteFile(keyPath, key, 0600); err != nil {
			return err
		}
		if err = os.WriteFile(certPath, []byte(cert), 0600); err != nil {
			return err
		}
	}
	if err = os.WriteFile(credentialsPath, []byte(secret), 0600); err != nil {
		return err
	}
	c.EndpointID = stringValue(response["endpoint_id"])
	c.CompanyID = stringValue(response["company_id"])
	c.BranchID = stringValue(response["branch_id"])
	return saveConfig(c)
}

func verifyEnrollmentResponse(response map[string]interface{}, pubkeyB64, expectedNonce string) error {
	pubkey, err := base64.StdEncoding.DecodeString(pubkeyB64)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return errors.New("invalid build-pinned server signing key")
	}
	if nonce, _ := response["enrollment_nonce"].(string); nonce != expectedNonce {
		return errors.New("enrollment nonce mismatch")
	}
	signatureB64, _ := response["enrollment_signature"].(string)
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid enrollment signature encoding")
	}
	proof := map[string]interface{}{}
	for _, key := range []string{"api_key", "endpoint_id", "server_ed25519_pubkey", "company_id", "branch_id", "client_cert_pem", "enrollment_nonce"} {
		value, exists := response[key]
		if !exists {
			return fmt.Errorf("enrollment response missing signed field %s", key)
		}
		proof[key] = value
	}
	message, err := json.Marshal(proof)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pubkey), message, signature) {
		return errors.New("invalid enrollment response signature")
	}
	return nil
}
func generateCSR() ([]byte, []byte, error) {
	host, _ := os.Hostname()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}}, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
func stringValue(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func capabilities() ([]string, map[string]interface{}) {
	caps := []string{"RUN_CMD", "REBOOT", "SHUTDOWN", "COLLECT_SYSINFO", "COLLECT_SOFTWARE", "COMPLIANCE_SCAN", "FILE_PUSH", "FILE_PULL", "LIST_DIRECTORY", "GET_EVENT_LOGS", "WINDOWS_UPDATE", "COLLECT_USERS", "CREATE_USER", "DELETE_USER", "RESET_PASSWORD", "DISABLE_USER", "ENABLE_USER", "GRANT_ELEVATION", "REVOKE_ELEVATION", "INSTALL_APP", "UPDATE_AGENT", "UNINSTALL_AGENT", "ROTATE_TLS_PINS"}
	if runtime.GOOS == "linux" {
		caps = append(caps, "UNINSTALL_APP")
	}
	details := map[string]interface{}{
		"remote_input":           false,
		"remote_clipboard":       false,
		"remote_consent":         false,
		"remote_process_manager": true,
	}
	if captureCommand() != "" {
		caps = append(caps, "SETUP_REMOTE_ACCESS", "REMOVE_REMOTE_ACCESS")
		if runtime.GOOS == "darwin" {
			_, clickErr := exec.LookPath("cliclick")
			_, scriptErr := exec.LookPath("osascript")
			details["remote_input"] = clickErr == nil && scriptErr == nil
			details["remote_clipboard"] = scriptErr == nil
			details["remote_consent"] = scriptErr == nil
		} else {
			_, inputErr := exec.LookPath("xdotool")
			_, clipboardErr := exec.LookPath("xclip")
			details["remote_input"] = inputErr == nil
			details["remote_clipboard"] = clipboardErr == nil
			details["remote_consent"] = consentPromptAvailable()
		}
		if details["remote_input"] == true {
			details["remote_control"] = "Screen viewing and remote input are ready; local OS privacy permission may still be required"
		} else {
			details["remote_control"] = "View-only is ready; install xdotool on Linux or cliclick on macOS to enable remote input"
		}
	} else {
		details["remote_control"] = "Install scrot or ImageMagick on Linux; macOS requires /usr/sbin/screencapture"
	}
	sort.Strings(caps)
	return caps, details
}

func heartbeat(jobCapacity int) ([]json.RawMessage, error) {
	host, _ := os.Hostname()
	cp := 0.0
	if values, _ := cpuPkg.Percent(time.Second, false); len(values) > 0 {
		cp = values[0]
	}
	rp := 0.0
	if m, _ := memPkg.VirtualMemory(); m != nil {
		rp = m.UsedPercent
	}
	free := 0.0
	if d, _ := diskPkg.Usage("/"); d != nil {
		free = float64(d.Free) / (1 << 30)
	}
	caps, details := capabilities()
	var result struct {
		Commands []json.RawMessage `json:"commands"`
	}
	if err := post("/api/agent/heartbeat", map[string]interface{}{"hostname": host, "cpu_pct": cp, "ram_used_pct": rp, "disk_free_gb": free, "agent_version": agentVersion, "agent_uptime_sec": int(time.Since(startedAt).Seconds()), "job_capacity": jobCapacity, "platform": runtime.GOOS, "capabilities": caps, "capability_details": details}, true, &result); err != nil {
		return nil, err
	}
	return result.Commands, nil
}

var startedAt = time.Now()

func verifyEnvelope(raw []byte, pub ed25519.PublicKey) (*Envelope, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var sigText string
	if err := json.Unmarshal(fields["signature"], &sigText); err != nil {
		return nil, errors.New("missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil {
		return nil, err
	}
	delete(fields, "signature")
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	msg := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			msg = append(msg, ',')
		}
		kb, _ := json.Marshal(k)
		msg = append(msg, kb...)
		msg = append(msg, ':')
		msg = append(msg, fields[k]...)
	}
	msg = append(msg, '}')
	if !ed25519.Verify(pub, msg, sig) {
		return nil, errors.New("invalid job signature")
	}
	var env Envelope
	if err = json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !jobIDPattern.MatchString(env.JobID) || env.Nonce == "" {
		return nil, errors.New("invalid envelope")
	}
	now := time.Now().Unix()
	if now > env.ExpiresAt || env.IssuedAt > now+60 {
		return nil, errors.New("expired or future envelope")
	}
	return &env, nil
}
func processJob(raw []byte, pub ed25519.PublicKey) {
	env, err := verifyEnvelope(raw, pub)
	if err != nil {
		log.Printf("rejected command: %v", err)
		return
	}
	if previous, ok := getCompletedJob(env.JobID); ok {
		if err := queuePendingReport(env.JobID, previous); err != nil {
			log.Printf("persist duplicate job report: %v", err)
		}
		flushPendingJobResults()
		return
	}
	if err := checkAndConsumeNonce(env.Nonce, env.ExpiresAt); err != nil {
		log.Printf("rejected command: %v", err)
		return
	}
	code, out, runErr := dispatch(env)
	status := "completed"
	message := ""
	if runErr != nil || code != 0 {
		status = "failed"
		if runErr != nil {
			message = runErr.Error()
		}
	}
	if len(out) > 1<<20 {
		out = out[:1<<20]
	}
	if len(message) > 16384 {
		message = message[:16384]
	}
	result := completedJob{Status: status, ExitCode: code, LogOutput: out, ErrorMsg: message}
	if err = recordCompletedJob(env.JobID, result); err != nil {
		log.Printf("persist completed job: %v", err)
		return
	}
	flushPendingJobResults()
}

func dispatch(env *Envelope) (int, string, error) {
	p := env.Payload
	switch env.Operation {
	case "COLLECT_SYSINFO":
		return simple(reportSysinfo())
	case "COLLECT_SOFTWARE":
		return simple(reportSoftware())
	case "COLLECT_USERS":
		return simple(reportUsers())
	case "RUN_CMD":
		return runWhitelisted(stringValue(p["cmd_type"]))
	case "REBOOT", "SHUTDOWN":
		return power(env.Operation, p)
	case "CREATE_USER", "DELETE_USER", "RESET_PASSWORD", "DISABLE_USER", "ENABLE_USER", "GRANT_ELEVATION", "REVOKE_ELEVATION":
		return userAction(env.Operation, p)
	case "WINDOWS_UPDATE":
		return osUpdate(stringValue(p["action"]))
	case "GET_EVENT_LOGS":
		return systemLogs(env.JobID, p)
	case "COMPLIANCE_SCAN":
		return compliance(env.JobID, p)
	case "FILE_PUSH":
		return filePush(p)
	case "FILE_PULL":
		return filePull(env.JobID, p)
	case "LIST_DIRECTORY":
		return listDirectory(p)
	case "INSTALL_APP":
		return installApp(env.JobID, p)
	case "UNINSTALL_APP":
		return uninstallApp(p)
	case "UPDATE_AGENT":
		return updateAgent(p)
	case "SETUP_REMOTE_ACCESS":
		return setupRemote(p)
	case "REMOVE_REMOTE_ACCESS":
		stopRemote()
		return 0, "Remote session stopped", nil
	case "UNINSTALL_AGENT":
		return selfRemove()
	case "ROTATE_TLS_PINS":
		return rotatePins(p)
	default:
		return 1, "", fmt.Errorf("operation %s is unsupported on %s", env.Operation, runtime.GOOS)
	}
}
func simple(err error) (int, string, error) {
	if err != nil {
		return 1, "", err
	}
	return 0, "Completed", nil
}

func systemInfo() map[string]interface{} {
	info := map[string]interface{}{"platform": runtime.GOOS, "os_name": runtime.GOOS, "arch": runtime.GOARCH}
	if h, err := hostPkg.Info(); err == nil {
		info["os_name"] = h.Platform
		info["os_version"] = h.PlatformVersion
		info["os_build"] = h.KernelVersion
	}
	if c, err := cpuPkg.Info(); err == nil && len(c) > 0 {
		info["cpu_model"] = c[0].ModelName
	}
	if m, err := memPkg.VirtualMemory(); err == nil {
		info["ram_total_gb"] = float64(m.Total) / (1 << 30)
	}
	if d, err := diskPkg.Usage("/"); err == nil {
		info["disk_total_gb"] = float64(d.Total) / (1 << 30)
		info["disk_free_gb"] = float64(d.Free) / (1 << 30)
	}
	host, _ := os.Hostname()
	info["hostname"] = host
	return info
}
func reportSysinfo() error { return post("/api/agent/sysinfo", systemInfo(), true, nil) }
func deviceIdentity() map[string]interface{} {
	serial := ""
	manufacturer := ""
	model := ""
	hardware := ""
	if runtime.GOOS == "linux" {
		hardware = firstFile("/sys/class/dmi/id/product_uuid", "/etc/machine-id")
		serial = firstFile("/sys/class/dmi/id/product_serial")
		manufacturer = firstFile("/sys/class/dmi/id/sys_vendor")
		model = firstFile("/sys/class/dmi/id/product_name")
	} else {
		out, _ := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		text := string(out)
		hardware = quotedProperty(text, "IOPlatformUUID")
		serial = quotedProperty(text, "IOPlatformSerialNumber")
		manufacturer = "Apple"
		model = commandText("sysctl", "-n", "hw.model")
	}
	return map[string]interface{}{"hardware_id": strings.ToLower(hardware), "serial_number": serial, "manufacturer": manufacturer, "model": model}
}
func firstFile(paths ...string) string {
	for _, p := range paths {
		if b, e := os.ReadFile(p); e == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}
func quotedProperty(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, `"`+key+`"`) {
			parts := strings.Split(line, " = ")
			if len(parts) == 2 {
				return strings.Trim(strings.TrimSpace(parts[1]), `"`)
			}
		}
	}
	return ""
}
func commandText(name string, args ...string) string {
	b, _ := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(b))
}

func reportUsers() error {
	type U struct {
		Username      string `json:"username"`
		DisplayName   string `json:"display_name"`
		SID           string `json:"sid"`
		PrincipalName string `json:"principal_name"`
		AccountType   string `json:"account_type"`
		DomainName    string `json:"domain_name"`
		IsAdmin       bool   `json:"is_admin"`
		IsEnabled     bool   `json:"is_enabled"`
	}
	admins := adminUsers()
	users := []U{}
	if runtime.GOOS == "linux" {
		b, _ := os.ReadFile("/etc/passwd")
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 7 {
				continue
			}
			uid, _ := strconv.Atoi(f[2])
			if uid < 1000 && uid != 0 {
				continue
			}
			users = append(users, U{f[0], strings.Split(f[4], ",")[0], "", f[0], "local", "", admins[f[0]], !strings.Contains(f[6], "nologin") && !strings.Contains(f[6], "false")})
		}
	} else {
		out, _ := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) != 2 {
				continue
			}
			uid, _ := strconv.Atoi(f[1])
			if uid < 500 {
				continue
			}
			users = append(users, U{Username: f[0], PrincipalName: f[0], AccountType: "local", IsAdmin: admins[f[0]], IsEnabled: true})
		}
	}
	return post("/api/agent/users", map[string]interface{}{"users": users}, true, nil)
}
func adminUsers() map[string]bool {
	m := map[string]bool{}
	var out string
	if runtime.GOOS == "darwin" {
		out = commandText("dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	} else {
		out = commandText("getent", "group", "sudo")
		out += " " + commandText("getent", "group", "wheel")
	}
	for _, u := range regexp.MustCompile(`[,: ]+`).Split(out, -1) {
		m[u] = true
	}
	m["root"] = true
	return m
}

func reportSoftware() error {
	type S struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Publisher   string `json:"publisher"`
		InstallDate string `json:"install_date"`
	}
	items := []S{}
	if runtime.GOOS == "linux" {
		if _, e := exec.LookPath("dpkg-query"); e == nil {
			out, _ := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
			for _, l := range strings.Split(string(out), "\n") {
				f := strings.SplitN(l, "\t", 2)
				if len(f) == 2 {
					items = append(items, S{Name: f[0], Version: f[1], Publisher: "dpkg"})
				}
			}
		} else if _, e := exec.LookPath("rpm"); e == nil {
			out, _ := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
			for _, l := range strings.Split(string(out), "\n") {
				f := strings.SplitN(l, "\t", 2)
				if len(f) == 2 {
					items = append(items, S{Name: f[0], Version: f[1], Publisher: "rpm"})
				}
			}
		}
	} else {
		out, _ := exec.Command("system_profiler", "SPApplicationsDataType", "-json").Output()
		var root map[string][]map[string]interface{}
		if json.Unmarshal(out, &root) == nil {
			for _, v := range root["SPApplicationsDataType"] {
				items = append(items, S{Name: stringValue(v["_name"]), Version: stringValue(v["version"]), Publisher: stringValue(v["obtained_from"])})
			}
		}
	}
	return post("/api/agent/software", map[string]interface{}{"software": items}, true, nil)
}

func runWhitelisted(kind string) (int, string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		switch kind {
		case "system_info":
			cmd = exec.Command("system_profiler", "SPSoftwareDataType", "SPHardwareDataType")
		case "clear_temp":
			cmd = exec.Command("find", "/private/tmp", "-mindepth", "1", "-mtime", "+2", "-delete")
		case "flush_dns":
			cmd = exec.Command("dscacheutil", "-flushcache")
		case "check_disk":
			cmd = exec.Command("diskutil", "verifyVolume", "/")
		}
	} else {
		switch kind {
		case "system_info":
			cmd = exec.Command("sh", "-c", "uname -a; cat /etc/os-release; lscpu 2>/dev/null")
		case "clear_temp":
			cmd = exec.Command("find", "/tmp", "-mindepth", "1", "-mtime", "+2", "-delete")
		case "flush_dns":
			if _, e := exec.LookPath("resolvectl"); e == nil {
				cmd = exec.Command("resolvectl", "flush-caches")
			} else {
				cmd = exec.Command("systemctl", "restart", "nscd")
			}
		case "check_disk":
			cmd = exec.Command("findmnt", "--verify")
		}
	}
	if cmd == nil {
		return 1, "", errors.New("command type is not whitelisted")
	}
	return runCommand(cmd, 5*time.Minute)
}
func runCommand(cmd *exec.Cmd, timeout time.Duration) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	wrapped := exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	wrapped.Stdin = cmd.Stdin
	wrapped.Env = cmd.Env
	wrapped.Dir = cmd.Dir
	out, err := wrapped.CombinedOutput()
	if len(out) > 1<<20 {
		out = out[:1<<20]
	}
	if ctx.Err() != nil {
		return 1, string(out), errors.New("command timed out")
	}
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			return x.ExitCode(), string(out), err
		}
		return 1, string(out), err
	}
	return 0, string(out), nil
}

func userAction(op string, p map[string]interface{}) (int, string, error) {
	u := stringValue(p["username"])
	if !usernamePattern.MatchString(u) {
		return 1, "", errors.New("invalid username")
	}
	password := stringValue(p["new_password"])
	if password == "" {
		password = stringValue(p["password"])
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		switch op {
		case "CREATE_USER":
			cmd = exec.Command("sysadminctl", "-addUser", u, "-password", stringValue(p["password"]), "-fullName", stringValue(p["full_name"]))
		case "DELETE_USER":
			cmd = exec.Command("sysadminctl", "-deleteUser", u)
		case "RESET_PASSWORD":
			cmd = exec.Command("sysadminctl", "-resetPasswordFor", u, "-newPassword", password)
		case "DISABLE_USER":
			cmd = exec.Command("pwpolicy", "-u", u, "-disableuser")
		case "ENABLE_USER":
			cmd = exec.Command("pwpolicy", "-u", u, "-enableuser")
		case "GRANT_ELEVATION":
			cmd = exec.Command("dseditgroup", "-o", "edit", "-a", u, "-t", "user", "admin")
		case "REVOKE_ELEVATION":
			cmd = exec.Command("dseditgroup", "-o", "edit", "-d", u, "-t", "user", "admin")
		}
	} else {
		switch op {
		case "CREATE_USER":
			cmd = exec.Command("useradd", "-m", "-c", stringValue(p["full_name"]), u)
		case "DELETE_USER":
			cmd = exec.Command("userdel", "-r", u)
		case "DISABLE_USER":
			cmd = exec.Command("usermod", "-L", u)
		case "ENABLE_USER":
			cmd = exec.Command("usermod", "-U", u)
		case "GRANT_ELEVATION":
			group := "sudo"
			if commandText("getent", "group", "sudo") == "" {
				group = "wheel"
			}
			cmd = exec.Command("usermod", "-aG", group, u)
		case "REVOKE_ELEVATION":
			group := "sudo"
			if commandText("getent", "group", "sudo") == "" {
				group = "wheel"
			}
			cmd = exec.Command("gpasswd", "-d", u, group)
		case "RESET_PASSWORD":
			cmd = exec.Command("chpasswd")
			cmd.Stdin = strings.NewReader(u + ":" + password + "\n")
		}
	}
	if cmd == nil {
		return 1, "", errors.New("unsupported user operation")
	}
	if op == "GRANT_ELEVATION" {
		duration := int64(intValue(p["duration_minutes"], 60))
		if err := recordElevationExpiry(u, duration); err != nil {
			return 1, "", fmt.Errorf("persist elevation expiry: %w", err)
		}
	}
	code, out, err := runCommand(cmd, 2*time.Minute)
	if err != nil && op == "GRANT_ELEVATION" {
		_ = removeElevationExpiry(u)
	}
	if err == nil && op == "REVOKE_ELEVATION" {
		if persistErr := removeElevationExpiry(u); persistErr != nil {
			return 1, out, fmt.Errorf("persist elevation revocation: %w", persistErr)
		}
	}
	if err == nil && op == "CREATE_USER" && password != "" && runtime.GOOS == "linux" {
		c := exec.Command("chpasswd")
		c.Stdin = strings.NewReader(u + ":" + password + "\n")
		code, out, err = runCommand(c, time.Minute)
	}
	return code, out, err
}

func power(op string, p map[string]interface{}) (int, string, error) {
	delay := intValue(p["delay_seconds"], 30)
	if runtime.GOOS == "darwin" {
		script := "tell application \"System Events\" to shut down"
		if op == "REBOOT" {
			script = "tell application \"System Events\" to restart"
		}
		cmd := exec.Command("sh", "-c", fmt.Sprintf("sleep %d; /usr/bin/osascript -e %s", delay, strconv.Quote(script)))
		return startDetached(cmd, "power action scheduled")
	}
	flag := "-P"
	if op == "REBOOT" {
		flag = "-r"
	}
	minutes := strconv.Itoa((delay + 59) / 60)
	return runCommand(exec.Command("shutdown", flag, "+"+minutes, "Warden scheduled action"), time.Minute)
}
func startDetached(cmd *exec.Cmd, msg string) (int, string, error) {
	if err := cmd.Start(); err != nil {
		return 1, "", err
	}
	return 0, msg, nil
}
func intValue(v interface{}, fallback int) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return fallback
}

func osUpdate(action string) (int, string, error) {
	if action == "" {
		action = "check"
	}
	if runtime.GOOS == "darwin" {
		args := []string{"-l"}
		if action == "install" {
			args = []string{"-ia", "--restart"}
		}
		return runCommand(exec.Command("softwareupdate", args...), 2*time.Hour)
	}
	var cmd *exec.Cmd
	if _, e := exec.LookPath("apt-get"); e == nil {
		if action == "install" {
			cmd = exec.Command("apt-get", "-y", "upgrade")
		} else {
			cmd = exec.Command("apt-get", "update")
		}
	} else if _, e := exec.LookPath("dnf"); e == nil {
		args := []string{"check-update"}
		if action == "install" {
			args = []string{"-y", "upgrade"}
		}
		cmd = exec.Command("dnf", args...)
	} else if _, e := exec.LookPath("yum"); e == nil {
		cmd = exec.Command("yum", "-y", "update")
	} else if _, e := exec.LookPath("zypper"); e == nil {
		cmd = exec.Command("zypper", "--non-interactive", "update")
	} else if _, e := exec.LookPath("pacman"); e == nil {
		cmd = exec.Command("pacman", "-Syu", "--noconfirm")
	}
	if cmd == nil {
		return 1, "", errors.New("no supported package manager")
	}
	return runCommand(cmd, 2*time.Hour)
}

func systemLogs(jobID string, p map[string]interface{}) (int, string, error) {
	var code int
	var output string
	var err error
	if runtime.GOOS == "darwin" {
		code, output, err = runCommand(exec.Command("log", "show", "--last", "30m", "--style", "compact"), 2*time.Minute)
	} else if _, e := exec.LookPath("journalctl"); e == nil {
		code, output, err = runCommand(exec.Command("journalctl", "--since", "30 minutes ago", "--no-pager", "-n", "500"), 2*time.Minute)
	} else {
		code, output, err = runCommand(exec.Command("tail", "-n", "500", "/var/log/syslog"), time.Minute)
	}
	if err != nil {
		return code, output, err
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = []string{}
	}
	events, _ := json.Marshal(lines)
	logName := stringValue(p["log_name"])
	if logName == "" {
		logName = "System"
	}
	if err = post("/api/agent/event-logs", map[string]interface{}{
		"job_id": jobID, "log_name": logName, "events_json": string(events),
	}, true, nil); err != nil {
		return 1, "", fmt.Errorf("report event logs: %w", err)
	}
	return 0, fmt.Sprintf("Collected %d system log entries", len(lines)), nil
}

func compliance(jobID string, p map[string]interface{}) (int, string, error) {
	type checkResult struct {
		Check  string `json:"check"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	results := []checkResult{}
	requested := map[string]bool{}
	if values, ok := p["checks"].([]interface{}); ok {
		for _, value := range values {
			if name, ok := value.(string); ok {
				requested[name] = true
			}
		}
	}
	wants := func(name string) bool { return len(requested) == 0 || requested[name] }
	if runtime.GOOS == "darwin" {
		if wants("firewall_enabled") {
			firewall := commandText("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
			firewallStatus := "fail"
			if strings.Contains(strings.ToLower(firewall), "enabled") {
				firewallStatus = "pass"
			}
			results = append(results, checkResult{"firewall_enabled", firewallStatus, firewall})
		}
		if wants("disk_encryption_enabled") {
			encryption := commandText("fdesetup", "status")
			encryptionStatus := "fail"
			if strings.Contains(strings.ToLower(encryption), "on") {
				encryptionStatus = "pass"
			}
			results = append(results, checkResult{"disk_encryption_enabled", encryptionStatus, encryption})
		}
	} else if wants("firewall_enabled") {
		firewall := commandText("sh", "-c", "if command -v ufw >/dev/null; then ufw status; elif command -v firewall-cmd >/dev/null; then firewall-cmd --state; elif command -v nft >/dev/null; then nft list ruleset; fi")
		status := "fail"
		lower := strings.ToLower(firewall)
		if strings.Contains(lower, "active") || strings.Contains(lower, "running") || strings.Contains(lower, "table") {
			status = "pass"
		}
		results = append(results, checkResult{"firewall_enabled", status, firewall})
	}
	if len(results) == 0 {
		return 1, "", errors.New("no requested compliance checks are supported on this platform")
	}
	passed := 0
	for _, result := range results {
		if result.Status == "pass" {
			passed++
		}
	}
	score := 0
	if len(results) > 0 {
		score = passed * 100 / len(results)
	}
	overall := "non_compliant"
	if passed == len(results) {
		overall = "compliant"
	}
	payload := map[string]interface{}{"job_id": jobID, "policy_id": stringValue(p["policy_id"]), "overall_status": overall, "score": score, "results": results}
	b, _ := json.Marshal(payload)
	if err := post("/api/agent/compliance-result", payload, true, nil); err != nil {
		return 1, string(b), fmt.Errorf("report compliance result: %w", err)
	}
	return 0, string(b), nil
}

func safePath(v interface{}) (string, error) {
	p := filepath.Clean(stringValue(v))
	if !filepath.IsAbs(p) {
		return "", errors.New("absolute path required")
	}
	allowedRoots := []string{"/tmp", "/private/tmp"}
	if runtime.GOOS == "darwin" {
		allowedRoots = append(allowedRoots, "/Users")
	} else {
		allowedRoots = append(allowedRoots, "/home")
	}
	allowed := false
	for _, root := range allowedRoots {
		if p == root || strings.HasPrefix(p, root+string(os.PathSeparator)) {
			allowed = true
			break
		}
	}
	if !allowed || p == dataDir || strings.HasPrefix(p, dataDir+string(os.PathSeparator)) {
		return "", errors.New("path must be inside a user profile or temporary folder")
	}
	return p, nil
}
func filePush(p map[string]interface{}) (int, string, error) {
	path, err := safePath(p["path"])
	if err != nil {
		return 1, "", err
	}
	raw, err := base64.StdEncoding.DecodeString(stringValue(p["content_b64"]))
	if err != nil || len(raw) > 8<<20 {
		return 1, "", errors.New("invalid or oversized file")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0755); err == nil {
		err = os.WriteFile(path, raw, 0600)
	}
	if err != nil {
		return 1, "", err
	}
	return 0, "File written", nil
}
func filePull(jobID string, p map[string]interface{}) (int, string, error) {
	path, err := safePath(p["path"])
	if err != nil {
		return 1, "", err
	}
	downloadName := filepath.Base(path)
	info, err := os.Stat(path)
	if err != nil {
		return 1, "", err
	}
	var b []byte
	if info.IsDir() {
		b, err = zipDirectory(path, 8<<20)
		downloadName += ".zip"
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return 1, "", err
	}
	if len(b) > 8<<20 {
		return 1, "", errors.New("file or archive exceeds 8 MiB")
	}
	if err := post("/api/agent/file-content", map[string]interface{}{
		"job_id": jobID, "path": path, "download_name": downloadName,
		"content_b64": base64.StdEncoding.EncodeToString(b), "size_bytes": len(b),
	}, true, nil); err != nil {
		return 1, "", err
	}
	return 0, fmt.Sprintf("File %s pulled (%d bytes)", path, len(b)), nil
}

func zipDirectory(root string, maxBytes int) ([]byte, error) {
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}
		writer, err := zw.CreateHeader(header)
		if err != nil || info.IsDir() {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, io.LimitReader(file, int64(maxBytes-buffer.Len()+1)))
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if buffer.Len() > maxBytes {
			return errors.New("directory archive exceeds 8 MiB")
		}
		return nil
	})
	if err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err = zw.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > maxBytes {
		return nil, errors.New("directory archive exceeds 8 MiB")
	}
	return buffer.Bytes(), nil
}
func listDirectory(p map[string]interface{}) (int, string, error) {
	requested := stringValue(p["path"])
	if requested == "" || requested == "::folders::" {
		items := []map[string]interface{}{}
		base := "/home"
		if runtime.GOOS == "darwin" {
			base = "/Users"
		}
		profiles, _ := os.ReadDir(base)
		for _, profile := range profiles {
			if !profile.IsDir() {
				continue
			}
			for _, folder := range []string{"Desktop", "Documents", "Downloads"} {
				path := filepath.Join(base, profile.Name(), folder)
				if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
					items = append(items, map[string]interface{}{"name": profile.Name() + " — " + folder, "path": path, "is_dir": true, "size": 0})
				}
			}
		}
		b, _ := json.Marshal(map[string]interface{}{"path": "::folders::", "items": items})
		return 0, string(b), nil
	}
	path, err := safePath(p["path"])
	if err != nil {
		return 1, "", err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return 1, "", err
	}
	items := []map[string]interface{}{}
	for _, e := range entries {
		info, _ := e.Info()
		items = append(items, map[string]interface{}{"name": e.Name(), "is_dir": e.IsDir(), "size": func() int64 {
			if info != nil {
				return info.Size()
			}
			return 0
		}()})
	}
	b, _ := json.Marshal(map[string]interface{}{"path": path, "items": items})
	return 0, string(b), nil
}

func download(url, dest, expected string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Agent-Key", apiKey)
	clientMu.RLock()
	client := httpClient
	clientMu.RUnlock()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 201<<20))
	if err != nil {
		return err
	}
	if expected != "" {
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != strings.ToLower(expected) {
			return errors.New("SHA-256 mismatch")
		}
	}
	return os.WriteFile(dest, b, 0700)
}
func installApp(job string, p map[string]interface{}) (int, string, error) {
	url := stringValue(p["app_url"])
	if url == "" {
		return 1, "", errors.New("missing app URL")
	}
	ext := strings.TrimPrefix(strings.ToLower(stringValue(p["ext"])), ".")
	dest := filepath.Join(os.TempDir(), "warden-"+job+"."+ext)
	defer os.Remove(dest)
	if err := download(url, dest, stringValue(p["sha256"])); err != nil {
		return 1, "", err
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" && ext == "pkg" {
		cmd = exec.Command("installer", "-pkg", dest, "-target", "/")
	} else if ext == "deb" {
		cmd = exec.Command("dpkg", "-i", dest)
	} else if ext == "rpm" {
		cmd = exec.Command("rpm", "-U", dest)
	} else {
		return 1, "", errors.New("supported packages are .pkg, .deb and .rpm")
	}
	return runCommand(cmd, 30*time.Minute)
}
func uninstallApp(p map[string]interface{}) (int, string, error) {
	name := stringValue(p["name"])
	if name == "" {
		name = stringValue(p["app_name"])
	}
	if !regexp.MustCompile(`^[A-Za-z0-9+_.@-]{1,160}$`).MatchString(name) {
		return 1, "", errors.New("invalid package name")
	}
	if runtime.GOOS == "darwin" {
		return 1, "", errors.New("macOS packages require a tenant-provided removal script")
	}
	if _, e := exec.LookPath("apt-get"); e == nil {
		return runCommand(exec.Command("apt-get", "-y", "remove", name), 30*time.Minute)
	}
	if _, e := exec.LookPath("dnf"); e == nil {
		return runCommand(exec.Command("dnf", "-y", "remove", name), 30*time.Minute)
	}
	return runCommand(exec.Command("rpm", "-e", name), 30*time.Minute)
}

func updateAgent(p map[string]interface{}) (int, string, error) {
	url := stringValue(p["download_url"])
	if url == "" {
		return 1, "", errors.New("missing update URL")
	}
	staged := filepath.Join(dataDir, "warden-agent.update")
	if err := download(url, staged, stringValue(p["sha256"])); err != nil {
		return 1, "", err
	}
	if err := os.Chmod(staged, 0755); err != nil {
		return 1, "", err
	}
	if code, output, err := runCommand(exec.Command(staged, "capabilities"), 30*time.Second); err != nil || code != 0 {
		_ = os.Remove(staged)
		return 1, output, fmt.Errorf("staged agent self-check failed: %w", err)
	}
	dest := filepath.Join(installDir, "warden-agent")
	backup := filepath.Join(dataDir, "warden-agent.previous")
	script := filepath.Join(os.TempDir(), fmt.Sprintf("warden-update-%d.sh", os.Getpid()))
	content := "#!/bin/sh\nsleep 3\nset -u\n" +
		"cp " + strconv.Quote(dest) + " " + strconv.Quote(backup) + " || exit 1\n" +
		"mv " + strconv.Quote(staged) + " " + strconv.Quote(dest) + " || exit 1\n" +
		"chmod 755 " + strconv.Quote(dest) + "\n"
	if runtime.GOOS == "darwin" {
		content += "launchctl kickstart -k system/com.warden.agent\nsleep 15\n" +
			"if launchctl print system/com.warden.agent >/dev/null 2>&1; then rm -f " + strconv.Quote(backup) + "; else mv " + strconv.Quote(backup) + " " + strconv.Quote(dest) + "; launchctl kickstart -k system/com.warden.agent; fi\n"
	} else {
		content += "systemctl restart warden-agent.service\nsleep 15\n" +
			"if systemctl is-active --quiet warden-agent.service; then rm -f " + strconv.Quote(backup) + "; else mv " + strconv.Quote(backup) + " " + strconv.Quote(dest) + "; systemctl restart warden-agent.service; fi\n"
	}
	content += "rm -f \"$0\"\n"
	if err := os.WriteFile(script, []byte(content), 0700); err != nil {
		return 1, "", err
	}
	return startDetached(exec.Command("sh", script), "Agent update scheduled")
}

func captureCommand() string {
	if runtime.GOOS == "darwin" {
		if _, e := os.Stat("/usr/sbin/screencapture"); e == nil {
			return "/usr/sbin/screencapture"
		}
		return ""
	}
	for _, n := range []string{"scrot", "import"} {
		if p, e := exec.LookPath(n); e == nil {
			return p
		}
	}
	return ""
}
func captureFrame() (string, []byte, error) {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("warden-screen-%d.jpg", os.Getpid()))
	var cmd *exec.Cmd
	tool := captureCommand()
	if runtime.GOOS == "darwin" {
		cmd = macSessionCommand(tool, "-x", "-t", "jpg", path)
	} else if strings.HasSuffix(tool, "scrot") {
		cmd = exec.Command(tool, "-q", "55", path)
	} else {
		cmd = exec.Command(tool, "-window", "root", "-quality", "55", path)
	}
	env := desktopEnv()
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return path, nil, fmt.Errorf("screen capture failed: %v: %s", err, out)
	}
	b, err := os.ReadFile(path)
	os.Remove(path)
	return path, b, err
}
func macSessionCommand(name string, args ...string) *exec.Cmd {
	uid := commandText("stat", "-f", "%u", "/dev/console")
	user := commandText("stat", "-f", "%Su", "/dev/console")
	if uid == "" || uid == "0" || user == "" || user == "root" {
		return exec.Command(name, args...)
	}
	wrapped := []string{"asuser", uid, "sudo", "-u", user, name}
	wrapped = append(wrapped, args...)
	return exec.Command("launchctl", wrapped...)
}
func desktopEnv() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	display := os.Getenv("DISPLAY")
	if display == "" {
		display = ":0"
	}
	auth := os.Getenv("XAUTHORITY")
	if auth == "" {
		for _, home := range []string{"/home/" + commandText("sh", "-c", "loginctl list-sessions --no-legend 2>/dev/null | awk 'NR==1{print $3}'"), "/root"} {
			candidate := filepath.Join(home, ".Xauthority")
			if _, e := os.Stat(candidate); e == nil {
				auth = candidate
				break
			}
		}
	}
	return []string{"DISPLAY=" + display, "XAUTHORITY=" + auth}
}
func setupRemote(p map[string]interface{}) (int, string, error) {
	url := stringValue(p["relay_url"])
	sessionID := stringValue(p["session_id"])
	if url == "" {
		return 1, "", errors.New("missing relay URL")
	}
	if required, _ := p["consent_required"].(bool); required {
		helper := strings.TrimSpace(stringValue(p["helper_name"]))
		reason := strings.TrimSpace(stringValue(p["reason"]))
		if helper == "" {
			helper = "A Warden technician"
		}
		if reason == "" {
			reason = "Interactive support"
		}
		if err := requestRemoteConsent(sessionID, helper, reason); err != nil {
			return 1, "", err
		}
	}
	remoteMu.Lock()
	defer remoteMu.Unlock()
	if remoteActive != nil {
		return 1, "", errors.New("remote session already active")
	}
	session := &remoteSession{stop: make(chan struct{}), done: make(chan struct{})}
	remoteActive = session
	go remoteLoop(url, sessionID, session)
	return 0, "Remote session starting", nil
}

func consentPromptAvailable() bool {
	if runtime.GOOS == "darwin" {
		_, err := exec.LookPath("osascript")
		return err == nil
	}
	for _, name := range []string{"zenity", "kdialog", "xmessage"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

func remoteConsentCommand(ctx context.Context, message string) (*exec.Cmd, error) {
	if runtime.GOOS == "darwin" {
		script := `on run argv
set response to display dialog (item 1 of argv) with title "Warden remote support" buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" giving up after 60
if gave up of response then error "expired"
if button returned of response is not "Allow" then error "denied"
end run`
		uid := commandText("stat", "-f", "%u", "/dev/console")
		user := commandText("stat", "-f", "%Su", "/dev/console")
		if uid == "" || uid == "0" || user == "" || user == "root" {
			return nil, errors.New("no interactive macOS user is signed in")
		}
		return exec.CommandContext(ctx, "launchctl", "asuser", uid, "sudo", "-u", user,
			"osascript", "-e", script, "--", message), nil
	}
	var cmd *exec.Cmd
	if path, err := exec.LookPath("zenity"); err == nil {
		cmd = exec.CommandContext(ctx, path, "--question", "--title=Warden remote support",
			"--ok-label=Allow", "--cancel-label=Deny", "--no-wrap", "--text="+message)
	} else if path, err := exec.LookPath("kdialog"); err == nil {
		cmd = exec.CommandContext(ctx, path, "--title", "Warden remote support", "--yesno", message,
			"--yes-label", "Allow", "--no-label", "Deny")
	} else if path, err := exec.LookPath("xmessage"); err == nil {
		cmd = exec.CommandContext(ctx, path, "-center", "-title", "Warden remote support",
			"-buttons", "Allow:0,Deny:2", "-default", "Deny", message)
	} else {
		return nil, errors.New("no supported desktop consent dialog is installed (zenity, kdialog, or xmessage)")
	}
	cmd.Env = append(os.Environ(), desktopEnv()...)
	return cmd, nil
}

func requestRemoteConsent(sessionID, helperName, reason string) error {
	helperName = strings.Join(strings.Fields(helperName), " ")
	reason = strings.Join(strings.Fields(reason), " ")
	if len(helperName) > 160 {
		helperName = helperName[:160]
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	message := fmt.Sprintf("%s is requesting remote access to this computer.\n\nReason: %s\n\nAllow this session?", helperName, reason)
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	cmd, err := remoteConsentCommand(ctx, message)
	if err != nil {
		_ = post("/api/agent/remote-consent", map[string]interface{}{"session_id": sessionID, "status": "denied"}, true, nil)
		return fmt.Errorf("could not display consent prompt: %w", err)
	}
	out, runErr := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded || strings.Contains(strings.ToLower(string(out)), "expired") {
		_ = post("/api/agent/remote-consent", map[string]interface{}{"session_id": sessionID, "status": "expired"}, true, nil)
		return errors.New("remote consent prompt expired")
	}
	if runErr != nil {
		_ = post("/api/agent/remote-consent", map[string]interface{}{"session_id": sessionID, "status": "denied"}, true, nil)
		return errors.New("remote user denied access")
	}
	if err := post("/api/agent/remote-consent", map[string]interface{}{"session_id": sessionID, "status": "approved"}, true, nil); err != nil {
		return fmt.Errorf("record approved remote consent: %w", err)
	}
	return nil
}
func stopRemote() {
	remoteMu.Lock()
	session := remoteActive
	if session != nil {
		select {
		case <-session.stop:
		default:
			close(session.stop)
		}
	}
	remoteMu.Unlock()
	if session != nil {
		select {
		case <-session.done:
		case <-time.After(3 * time.Second):
		}
	}
}
func reportRemoteFailure(sessionID string, err error) {
	if sessionID == "" || err == nil {
		return
	}
	_ = post("/api/agent/remote-relay-failed", map[string]interface{}{"session_id": sessionID, "reason": err.Error()}, true, nil)
}
func remoteLoop(url, sessionID string, session *remoteSession) {
	defer func() {
		close(session.done)
		remoteMu.Lock()
		if remoteActive == session {
			remoteActive = nil
		}
		remoteMu.Unlock()
	}()
	_ = post("/api/agent/remote-consent", map[string]interface{}{"session_id": sessionID, "status": "not_required"}, true, nil)
	c := configSnapshot()
	t, err := tlsConfig(pins(), c.TLSTrustMode)
	if err != nil {
		log.Printf("remote TLS: %v", err)
		reportRemoteFailure(sessionID, err)
		return
	}
	dial := websocket.Dialer{TLSClientConfig: t, HandshakeTimeout: 20 * time.Second}
	conn, _, err := dial.Dial(url, http.Header{"X-Agent-Key": []string{apiKey}})
	if err != nil {
		log.Printf("remote dial: %v", err)
		reportRemoteFailure(sessionID, err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(1 << 20)
	writer := sync.Mutex{}
	writeJSONSafe := func(v interface{}) error { writer.Lock(); defer writer.Unlock(); return conn.WriteJSON(v) }
	writeBinary := func(b []byte) error {
		writer.Lock()
		defer writer.Unlock()
		return conn.WriteMessage(websocket.BinaryMessage, b)
	}
	_, frame, err := captureFrame()
	if err != nil {
		log.Printf("remote capture: %v", err)
		reportRemoteFailure(sessionID, err)
		return
	}
	cfgImg, err := jpeg.DecodeConfig(bytes.NewReader(frame))
	if err != nil {
		return
	}
	_ = writeJSONSafe(map[string]interface{}{"type": "init", "w": cfgImg.Width, "h": cfgImg.Height})
	_ = writeJSONSafe(map[string]interface{}{"type": "monitors", "monitors": []map[string]interface{}{{"id": 0, "name": "Display 1", "w": cfgImg.Width, "h": cfgImg.Height}}})
	_ = writeBinary(append([]byte{0}, frame...))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, b, e := conn.ReadMessage()
			if e != nil {
				return
			}
			handleRemoteInput(b, writeJSONSafe)
		}
	}()
	tick := time.NewTicker(350 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-session.stop:
			return
		case <-done:
			return
		case <-tick.C:
			_, b, e := captureFrame()
			if e == nil {
				if writeBinary(append([]byte{0}, b...)) != nil {
					return
				}
			}
		}
	}
}
func handleRemoteInput(raw []byte, reply func(interface{}) error) {
	var e map[string]interface{}
	if json.Unmarshal(raw, &e) != nil {
		return
	}
	kind := stringValue(e["type"])
	x, y := intValue(e["x"], 0), intValue(e["y"], 0)
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("xdotool"); err != nil {
			return
		}
		args := []string{}
		switch kind {
		case "mousemove":
			args = []string{"mousemove", strconv.Itoa(x), strconv.Itoa(y)}
		case "mousedown":
			args = []string{"mousemove", strconv.Itoa(x), strconv.Itoa(y), "mousedown", mouseButton(stringValue(e["button"]))}
		case "mouseup":
			args = []string{"mousemove", strconv.Itoa(x), strconv.Itoa(y), "mouseup", mouseButton(stringValue(e["button"]))}
		case "scroll":
			button := "5"
			if intValue(e["delta"], 1) < 0 {
				button = "4"
			}
			args = []string{"click", button}
		case "keydown":
			args = []string{"keydown", keyName(stringValue(e["key"]))}
		case "keyup":
			args = []string{"keyup", keyName(stringValue(e["key"]))}
		case "clipboard_write":
			cmd := exec.Command("xclip", "-selection", "clipboard")
			cmd.Stdin = strings.NewReader(stringValue(e["text"]))
			_ = cmd.Run()
			return
		case "process_list":
			processList(reply)
			return
		case "process_kill":
			_ = exec.Command("kill", strconv.Itoa(intValue(e["pid"], 0))).Run()
			return
		default:
			return
		}
		cmd := exec.Command("xdotool", args...)
		cmd.Env = append(os.Environ(), desktopEnv()...)
		_ = cmd.Run()
		return
	}
	// macOS uses cliclick when available; keyboard and clipboard have native
	// AppleScript fallbacks. Accessibility permission is deliberately left to
	// the local user/MDM privacy policy.
	if _, err := exec.LookPath("cliclick"); err == nil && (strings.HasPrefix(kind, "mouse") || kind == "scroll") {
		token := "m:" + strconv.Itoa(x) + "," + strconv.Itoa(y)
		if kind == "mousedown" {
			token = "dd:" + strconv.Itoa(x) + "," + strconv.Itoa(y)
		} else if kind == "mouseup" {
			token = "du:" + strconv.Itoa(x) + "," + strconv.Itoa(y)
		}
		_ = macSessionCommand("cliclick", token).Run()
		return
	}
	switch kind {
	case "mousedown":
		fallthrough
	case "mouseup":
		if kind == "mouseup" {
			_ = macSessionCommand("osascript", "-e", fmt.Sprintf("tell application \"System Events\" to click at {%d,%d}", x, y)).Run()
		}
	case "keydown":
		_ = macSessionCommand("osascript", "-e", fmt.Sprintf("tell application \"System Events\" to key down %s", strconv.Quote(keyName(stringValue(e["key"]))))).Run()
	case "keyup":
		_ = macSessionCommand("osascript", "-e", fmt.Sprintf("tell application \"System Events\" to key up %s", strconv.Quote(keyName(stringValue(e["key"]))))).Run()
	case "clipboard_write":
		_ = macSessionCommand("osascript", "-e", "set the clipboard to "+strconv.Quote(stringValue(e["text"]))).Run()
	case "process_list":
		processList(reply)
	case "process_kill":
		_ = exec.Command("kill", strconv.Itoa(intValue(e["pid"], 0))).Run()
	}
}
func mouseButton(v string) string {
	if v == "right" {
		return "3"
	}
	if v == "middle" {
		return "2"
	}
	return "1"
}
func keyName(v string) string {
	m := map[string]string{"Control": "ctrl", "Meta": "super", "ArrowUp": "Up", "ArrowDown": "Down", "ArrowLeft": "Left", "ArrowRight": "Right", " ": "space"}
	if x := m[v]; x != "" {
		return x
	}
	return v
}
func processList(reply func(interface{}) error) {
	out, _ := exec.Command("ps", "-axo", "pid=,rss=,comm=").Output()
	items := []map[string]interface{}{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		rss, _ := strconv.ParseInt(f[1], 10, 64)
		items = append(items, map[string]interface{}{"Id": pid, "WorkingSet64": rss * 1024, "ProcessName": filepath.Base(strings.Join(f[2:], " "))})
		if len(items) >= 250 {
			break
		}
	}
	_ = reply(map[string]interface{}{"type": "process_list", "processes": items})
}

func rotatePins(p map[string]interface{}) (int, string, error) {
	raw, ok := p["fingerprints"].([]interface{})
	if !ok || len(raw) < 1 || len(raw) > 3 {
		return 1, "", errors.New("invalid fingerprint set")
	}
	next := []string{}
	for _, v := range raw {
		s := strings.ToLower(strings.ReplaceAll(stringValue(v), ":", ""))
		if len(s) != 64 {
			return 1, "", errors.New("invalid fingerprint")
		}
		next = append(next, s)
	}
	c := configSnapshot()
	c.CertFingerprints = next
	c.CertFingerprint = next[0]
	if err := saveConfig(c); err != nil {
		return 1, "", err
	}
	if err := initHTTP(); err != nil {
		return 1, "", err
	}
	return 0, "TLS pins rotated", nil
}
func selfRemove() (int, string, error) {
	script := filepath.Join(os.TempDir(), fmt.Sprintf("warden-remove-%d.sh", os.Getpid()))
	unit := "warden-agent.service"
	content := "#!/bin/sh\nsleep 3\n"
	if runtime.GOOS == "darwin" {
		content += "launchctl bootout system /Library/LaunchDaemons/com.warden.agent.plist 2>/dev/null || true\nrm -f /Library/LaunchDaemons/com.warden.agent.plist\n"
	} else {
		content += "systemctl disable --now " + unit + " 2>/dev/null || true\nrm -f /etc/systemd/system/" + unit + "\nsystemctl daemon-reload\n"
	}
	content += "rm -rf " + strconv.Quote(installDir) + " " + strconv.Quote(dataDir) + "\nrm -f \"$0\"\n"
	if err := os.WriteFile(script, []byte(content), 0700); err != nil {
		return 1, "", err
	}
	return startDetached(exec.Command("sh", script), "Agent removal scheduled")
}

func installService() error {
	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
	}
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dest := filepath.Join(installDir, "warden-agent")
	b, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if err = os.WriteFile(dest, b, 0755); err != nil {
		return err
	}
	sourceCfg := filepath.Join(filepath.Dir(exe), "config.json")
	if c, er := os.ReadFile(sourceCfg); er == nil {
		if er = os.WriteFile(configPath, c, 0600); er != nil {
			return er
		}
	}
	if runtime.GOOS == "darwin" {
		plist := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>com.warden.agent</string><key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/warden-agent</string><string>run</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>StandardOutPath</key><string>/var/log/warden-agent.log</string><key>StandardErrorPath</key><string>/var/log/warden-agent.log</string></dict></plist>`
		path := "/Library/LaunchDaemons/com.warden.agent.plist"
		if err = os.WriteFile(path, []byte(plist), 0644); err != nil {
			return err
		}
		_ = exec.Command("launchctl", "bootout", "system", path).Run()
		return exec.Command("launchctl", "bootstrap", "system", path).Run()
	}
	unit := "[Unit]\nDescription=Warden endpoint management agent\nAfter=network-online.target graphical.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/local/lib/warden-agent/warden-agent run\nRestart=always\nRestartSec=10\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n"
	if err = os.WriteFile("/etc/systemd/system/warden-agent.service", []byte(unit), 0644); err != nil {
		return err
	}
	if out, er := exec.Command("systemctl", "daemon-reload").CombinedOutput(); er != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", er, out)
	}
	out, er := exec.Command("systemctl", "enable", "--now", "warden-agent.service").CombinedOutput()
	if er != nil {
		return fmt.Errorf("systemctl enable: %v: %s", er, out)
	}
	return nil
}
func removeService() error {
	if os.Geteuid() != 0 {
		return errors.New("remove must run as root")
	}
	_, _, err := selfRemove()
	return err
}
