package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var buildAgentIntegrityVerification string
var installedIntegrityMu sync.Mutex
var installedIntegrityReport map[string]interface{}
var installedIntegrityChecked time.Time

func agentIntegrityMeasurement(proof map[string]string) string {
	core := map[string]string{}
	for _, key := range []string{"purpose", "endpoint_id", "agent_version", "sha256", "installation_id", "device_cert_sha256", "api_key_sha256"} {
		core[key] = proof[key]
	}
	raw, _ := json.Marshal(core)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func verifyAgentIntegrityProof(raw []byte, pubkeyB64, endpoint, version, observed, challenge string) error {
	var proof map[string]string
	if err := json.Unmarshal(raw, &proof); err != nil {
		return fmt.Errorf("invalid agent integrity proof")
	}
	signature, err := base64.StdEncoding.DecodeString(proof["signature"])
	if err != nil {
		return fmt.Errorf("invalid agent integrity signature")
	}
	delete(proof, "signature")
	if len(proof) != 9 || proof["purpose"] != "warden-agent-integrity-v2" || proof["endpoint_id"] != endpoint || proof["agent_version"] != version || proof["sha256"] != observed || len(observed) != 64 || proof["measurement_sha256"] != agentIntegrityMeasurement(proof) {
		return fmt.Errorf("agent integrity binding mismatch")
	}
	if challenge != "" && proof["challenge"] != challenge {
		return fmt.Errorf("agent integrity challenge mismatch")
	}
	public, err := loadServerPubkey(pubkeyB64)
	if err != nil {
		return err
	}
	message, err := json.Marshal(proof)
	if err != nil || !ed25519.Verify(public, message, signature) {
		return fmt.Errorf("untrusted agent integrity proof")
	}
	return nil
}

func verifyLocalAgentIntegrityProof(raw []byte, c AgentConfig, observed, challenge string) error {
	if err := verifyAgentIntegrityProof(raw, c.ServerEd25519Pubkey, c.EndpointID, agentVersion, observed, challenge); err != nil {
		return err
	}
	var proof map[string]string
	if err := json.Unmarshal(raw, &proof); err != nil {
		return err
	}
	certificate, ok, err := loadClientCertificate()
	if err != nil || !ok || len(certificate.Certificate) == 0 {
		return fmt.Errorf("device certificate unavailable")
	}
	certHash := sha256.Sum256(certificate.Certificate[0])
	keyHash := sha256.Sum256([]byte(apiKey))
	if proof["installation_id"] != c.InstallationID || proof["device_cert_sha256"] != hex.EncodeToString(certHash[:]) || proof["api_key_sha256"] != hex.EncodeToString(keyHash[:]) {
		return fmt.Errorf("installation identity measurement mismatch")
	}
	return nil
}

// Hash the installed executable at a bounded interval; never self-bless a
// checksum or stop the service merely because the server is temporarily down.
func installedAgentIntegrity() map[string]interface{} {
	c := getConfig()
	if !c.AgentIntegrityVerification && buildAgentIntegrityVerification != "true" {
		return nil
	}
	installedIntegrityMu.Lock()
	defer installedIntegrityMu.Unlock()
	if installedIntegrityReport != nil && time.Since(installedIntegrityChecked) < 5*time.Minute {
		return installedIntegrityReport
	}
	installedIntegrityChecked = time.Now()
	executable, err := os.Executable()
	if err != nil {
		return map[string]interface{}{"status": "unavailable"}
	}
	observed, err := fileSHA256(executable)
	if err != nil {
		return map[string]interface{}{"status": "unavailable"}
	}
	observed = strings.ToLower(observed)
	report := map[string]interface{}{"sha256": observed, "status": "unverified"}
	proofPath := filepath.Join(dataDir, "agent-integrity.json")
	previous, readErr := os.ReadFile(proofPath)
	if readErr == nil {
		var proof map[string]string
		if json.Unmarshal(previous, &proof) == nil && verifyLocalAgentIntegrityProof(previous, c, proof["sha256"], "") == nil {
			report["measurement_sha256"] = proof["measurement_sha256"]
			if proof["sha256"] == observed {
				report["status"] = "verified"
			} else {
				report["status"] = "mismatch"
			}
		}
	}
	challengeBytes := make([]byte, 32)
	if _, err = rand.Read(challengeBytes); err == nil {
		challenge := base64.StdEncoding.EncodeToString(challengeBytes)
		message := []byte("warden-agent-integrity-proof-v1|" + c.EndpointID + "|" + agentVersion + "|" + observed + "|" + challenge)
		cert, signature, proofErr := signWithDeviceKey(message)
		if proofErr != nil {
			installedIntegrityReport = report
			return report
		}
		raw, requestErr := apiPostRaw("/api/agent/integrity/manifest", map[string]interface{}{"challenge": challenge, "agent_version": agentVersion, "sha256": observed, "device_certificate": cert, "device_signature": signature}, true, heartbeatTimeoutSec)
		if requestErr == nil && verifyLocalAgentIntegrityProof(raw, c, observed, challenge) == nil {
			// A valid approved replacement may differ even at the same agent version.
			// Only a server-signed exact-build proof can replace the prior baseline.
			report["status"] = "verified"
			var proof map[string]string
			json.Unmarshal(raw, &proof)
			report["measurement_sha256"] = proof["measurement_sha256"]
			temp := proofPath + ".tmp"
			if err = os.WriteFile(temp, raw, 0600); err == nil {
				if err = os.Rename(temp, proofPath); err != nil {
					os.Remove(temp)
				}
			}
		}
	}
	installedIntegrityReport = report
	return report
}
