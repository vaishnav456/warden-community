package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestVerifyEnrollmentResponseBindsNonceAndCredentials(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]interface{}{
		"api_key": "secret", "endpoint_id": "endpoint", "company_id": "company",
		"branch_id": nil, "client_cert_pem": "certificate", "enrollment_nonce": "nonce",
		"server_ed25519_pubkey": base64.StdEncoding.EncodeToString(pub),
	}
	proof, _ := json.Marshal(response)
	response["enrollment_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, proof))
	if err := verifyEnrollmentResponse(response, base64.StdEncoding.EncodeToString(pub), "nonce"); err != nil {
		t.Fatalf("valid enrollment proof rejected: %v", err)
	}
	response["api_key"] = "substituted"
	if err := verifyEnrollmentResponse(response, base64.StdEncoding.EncodeToString(pub), "nonce"); err == nil {
		t.Fatal("tampered enrollment credential was accepted")
	}
}
