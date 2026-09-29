package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	dataDir = `C:\ProgramData\WardenAgent`
	// installDir holds the installed warden-agent.exe + service registration,
	// kept separate from dataDir so uninstall can remove the binary once the
	// service process has actually exited, without racing an open executable.
	installDir        = `C:\Program Files\WardenAgent`
	stagingDir        = `C:\ProgramData\WardenAgent\staging`
	configPath        = `C:\ProgramData\WardenAgent\config.json`
	credentialsPath   = `C:\ProgramData\WardenAgent\credentials.bin`
	noncesPath        = `C:\ProgramData\WardenAgent\nonces.dat`
	elevationsPath    = `C:\ProgramData\WardenAgent\elevations.json`
	logPath           = `C:\ProgramData\WardenAgent\agent.log`
	updateHealthPath  = `C:\ProgramData\WardenAgent\update-health.ok`
	pendingEnrollPath = `C:\ProgramData\WardenAgent\enrollment-pending.json`

	pollIntervalSec     = 30
	heartbeatTimeoutSec = 10
	jobTimeoutSec       = 300
	agentVersion        = "2.6.39"
)

type AgentConfig struct {
	ServerURL           string   `json:"server_url"`
	ServerEd25519Pubkey string   `json:"server_ed25519_pubkey"`
	CertFingerprint     string   `json:"cert_fingerprint"`
	CertFingerprints    []string `json:"cert_fingerprints,omitempty"`
	TLSTrustMode        string   `json:"tls_trust_mode,omitempty"`
	InstallationID      string   `json:"installation_id,omitempty"`
	CompanyID           string   `json:"company_id"`
	BranchID            string   `json:"branch_id"`
	EndpointID          string   `json:"endpoint_id"`
	// EnrollmentToken is only present in the bootstrap config.json the
	// build-service packages before an endpoint exists (see
	// build-service/builder.py, server/routes/endpoints.py:generate_installer)
	// — not persisted once real enrollment fields (EndpointID etc.) are
	// saved by doEnroll.
	EnrollmentToken string `json:"enrollment_token,omitempty"`
}

var (
	cfg   AgentConfig
	cfgMu sync.RWMutex

	// Set by build.bat via -ldflags. These pins seed config.json before the
	// first enrollment; later rotation is an authenticated, signed job that
	// must preserve overlap with the currently trusted set.
	buildServerURL           string
	buildServerEd25519Pubkey string
	buildCertFingerprint     string
	buildTLSTrustMode        string
	// Base64 keeps spaces and Unicode out of Go's -ldflags parser. It affects
	// only the Windows Services display label; serviceName stays stable.
	buildServiceDisplayNameB64 string
	// Set to "true" by the build pipeline whenever the running binary was
	// Authenticode signed. Signed agents then fail closed on unsigned or
	// untrusted self-updates. It remains false for development builds until
	// the production certificate is provisioned.
	buildRequireAuthenticode string
	// SHA-256 of the Credential Provider DLL packaged next to this exact
	// agent build. The installer refuses any adjacent DLL that does not match.
	buildCredentialProviderSHA256 string
)

func requireAuthenticodeUpdates() bool {
	return strings.EqualFold(strings.TrimSpace(buildRequireAuthenticode), "true")
}

func loadConfig() error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &cfg)
}

func saveConfig(c AgentConfig) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	ensureDirs()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, configPath); err != nil {
		return err
	}
	cfg = c
	return nil
}

func seedBuildConfig() error {
	if _, err := os.Stat(configPath); err == nil {
		return nil
	}
	if buildServerEd25519Pubkey == "" || (normalizeTLSTrustMode(buildTLSTrustMode) != "webpki" && buildCertFingerprint == "") {
		return nil
	}
	server := buildServerURL
	if server == "" {
		server = "https://warden.example.com"
	}
	installationID, err := newInstallationID()
	if err != nil {
		return err
	}
	return saveConfig(AgentConfig{
		ServerURL:           server,
		ServerEd25519Pubkey: buildServerEd25519Pubkey,
		CertFingerprint:     buildCertFingerprint,
		CertFingerprints:    []string{buildCertFingerprint},
		TLSTrustMode:        normalizeTLSTrustMode(buildTLSTrustMode),
		InstallationID:      installationID,
	})
}

func effectiveCertFingerprints(c AgentConfig) []string {
	if len(c.CertFingerprints) > 0 {
		return append([]string(nil), c.CertFingerprints...)
	}
	if c.CertFingerprint != "" {
		return []string{c.CertFingerprint}
	}
	return nil
}

func getConfig() AgentConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg
}

func serverURL() string {
	c := getConfig()
	if c.ServerURL != "" {
		return strings.TrimRight(c.ServerURL, "/")
	}
	if env := os.Getenv("WARDEN_SERVER_URL"); env != "" {
		return strings.TrimRight(env, "/")
	}
	return "https://warden.example.com"
}

func ensureDirs() {
	os.MkdirAll(dataDir, 0700)
	os.MkdirAll(stagingDir, 0700)
}

func isEnrolled() bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var stored AgentConfig
	if json.Unmarshal(data, &stored) != nil || stored.EndpointID == "" {
		return false
	}
	_, err = os.Stat(credentialsPath)
	return err == nil
}

// waitForEnrollmentOrTimeout polls isEnrolled() from the "install" CLI
// command's process — a separate process from the service instance
// Start() just launched, whose first enrollment (network round-trip +
// writing config.json/credentials.bin into dataDir) hasn't necessarily
// finished by the time Start() returns (see main.go's "install" case).
// Returns as soon as enrollment lands, or after max elapses either way —
// this is a best-effort wait, not a hard requirement, so a genuinely
// failed enrollment (bad token, no network) doesn't hang the install.
func waitForEnrollmentOrTimeout(max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if isEnrolled() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}
