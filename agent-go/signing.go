package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const maxCommandClockSkew = 60 * time.Second

// Envelope holds the parsed fields of a signed job envelope.
type Envelope struct {
	JobID      string                 `json:"job_id"`
	CompanyID  string                 `json:"company_id"`
	EndpointID string                 `json:"endpoint_id"`
	Nonce      string                 `json:"nonce"`
	IssuedAt   int64                  `json:"issued_at"`
	ExpiresAt  int64                  `json:"expires_at"`
	Operation  string                 `json:"operation"`
	Payload    map[string]interface{} `json:"payload"`
}

// loadServerPubkey decodes a base64 raw Ed25519 public key (32 bytes).
func loadServerPubkey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func verifyEnrollmentResponse(response map[string]interface{}, pubkeyB64, expectedNonce string) error {
	pubkey, err := loadServerPubkey(pubkeyB64)
	if err != nil {
		return err
	}
	nonce, _ := response["enrollment_nonce"].(string)
	if nonce == "" || nonce != expectedNonce {
		return fmt.Errorf("enrollment nonce mismatch")
	}
	signatureB64, _ := response["enrollment_signature"].(string)
	if signatureB64 == "" {
		return fmt.Errorf("enrollment response missing signature")
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid enrollment signature encoding: %w", err)
	}
	proof := map[string]interface{}{}
	for _, key := range []string{
		"api_key", "endpoint_id", "server_ed25519_pubkey", "company_id",
		"branch_id", "client_cert_pem", "enrollment_nonce",
	} {
		value, exists := response[key]
		if !exists {
			return fmt.Errorf("enrollment response missing signed field %s", key)
		}
		proof[key] = value
	}
	message, err := json.Marshal(proof)
	if err != nil {
		return fmt.Errorf("canonicalize enrollment response: %w", err)
	}
	if !ed25519.Verify(pubkey, message, signature) {
		return fmt.Errorf("invalid enrollment response signature")
	}
	return nil
}

// verifyEnvelope checks the Ed25519 signature, expiry, and clock skew.
// Returns the parsed Envelope on success.
// The rawJSON must be the full envelope JSON as received from the server.
func verifyEnvelope(rawJSON []byte, pubKey ed25519.PublicKey) (*Envelope, error) {
	// Parse into raw message map to preserve exact JSON byte representation
	// (avoids float serialization mismatches when re-encoding for verification).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rawJSON, &raw); err != nil {
		return nil, fmt.Errorf("invalid envelope JSON: %w", err)
	}

	// Extract signature
	sigRawMsg, ok := raw["signature"]
	if !ok {
		return nil, fmt.Errorf("envelope missing signature")
	}
	var sigB64 string
	if err := json.Unmarshal(sigRawMsg, &sigB64); err != nil {
		return nil, fmt.Errorf("invalid signature field")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("malformed signature: %w", err)
	}

	// Build canonical message (all fields except "signature", sorted)
	payload := make(map[string]json.RawMessage, len(raw)-1)
	for k, v := range raw {
		if k != "signature" {
			payload[k] = v
		}
	}
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	message := []byte{'{'}
	for i, key := range keys {
		if i > 0 {
			message = append(message, ',')
		}
		keyJSON, _ := json.Marshal(key)
		message = append(message, keyJSON...)
		message = append(message, ':')
		message = append(message, payload[key]...)
	}
	message = append(message, '}')

	// Verify Ed25519 signature
	if !ed25519.Verify(pubKey, message, sig) {
		return nil, fmt.Errorf("invalid job signature")
	}

	// Parse envelope fields for expiry checks
	var env Envelope
	if err := json.Unmarshal(rawJSON, &env); err != nil {
		return nil, fmt.Errorf("parse envelope fields: %w", err)
	}
	if !canonicalJobID.MatchString(env.JobID) {
		return nil, fmt.Errorf("envelope has invalid job_id")
	}
	if env.Nonce == "" {
		return nil, fmt.Errorf("envelope missing nonce")
	}
	if err := validateEnvelopeBinding(&env, getConfig()); err != nil {
		return nil, err
	}

	now := trustedCommandUnix()
	if now > env.ExpiresAt {
		return nil, fmt.Errorf("job envelope expired")
	}
	// Windows endpoints can drift by several seconds between time-service
	// synchronizations. Keep signature, expiry and durable nonce checks as the
	// security boundary, but tolerate a bounded amount of clock skew so valid
	// commands aren't rejected merely because the endpoint clock is behind.
	if env.IssuedAt > now+int64(maxCommandClockSkew/time.Second) {
		return nil, fmt.Errorf("job issued in the future")
	}

	return &env, nil
}

func validateEnvelopeBinding(env *Envelope, current AgentConfig) error {
	if current.CompanyID == "" || current.EndpointID == "" {
		return fmt.Errorf("agent is not enrolled for command execution")
	}
	if env.CompanyID == "" || env.EndpointID == "" {
		return fmt.Errorf("envelope missing tenant or endpoint binding")
	}
	if env.CompanyID != current.CompanyID || env.EndpointID != current.EndpointID {
		return fmt.Errorf("envelope tenant or endpoint binding mismatch")
	}
	return nil
}
