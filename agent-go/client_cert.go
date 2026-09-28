package main

// client_cert.go — mTLS client certificate generation and storage.
//
// Windows client-certificate storage. Companion to
// server/services/agent_ca.py. Generates this agent's own key pair
// locally at enrollment time — the private key is never transmitted
// anywhere, only a CSR (Certificate Signing Request, which contains just
// the public key + identity, no secret material). The server forwards
// that CSR to Warden's private device CA for signing; only the resulting
// certificate comes back over the network.
//
// Storage: the private key is DPAPI-encrypted at rest (same protection as
// credentials.bin's API key — see dpapi.go's saveAPIKey). The certificate
// itself is public (no secret material) and stored as plain PEM.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var (
	clientKeyPath  = filepath.Join(dataDir, "client_key.bin")
	clientCertPath = filepath.Join(dataDir, "client_cert.pem")
)

// generateCSR generates a new key pair + CSR. Returns (privateKeyPEM,
// csrPEM). The caller is responsible for persisting the private key
// (DPAPI-encrypted — see saveClientKey()) and submitting the CSR to the
// server. The Subject Common Name is just a hint; the server's own
// fingerprint cross-check (not anything in the CSR) is what actually binds
// the issued cert to this endpoint.
func generateCSR(endpointHint string) (keyPEM []byte, csrPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: endpointHint},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// saveClientKey DPAPI-encrypts and saves the client cert's private key,
// restricted to SYSTEM/Administrators — identical protection to
// dpapi.go's saveAPIKey.
func saveClientKey(keyPEM []byte) error {
	enc, err := encryptDPAPI(keyPEM, "WardenAgent mTLS Client Key")
	if err != nil {
		return fmt.Errorf("DPAPI encrypt: %w", err)
	}
	if err := os.WriteFile(clientKeyPath, enc, 0600); err != nil {
		return fmt.Errorf("write client key: %w", err)
	}
	out, err := exec.Command(
		"icacls", clientKeyPath, "/inheritance:r", "/grant:r",
		"SYSTEM:(F)", "Administrators:(F)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("restrict client key DACL: %w: %s", err, string(out))
	}
	return nil
}

// loadClientKeyPEM decrypts and returns the client cert's private key as
// PEM bytes.
func loadClientKeyPEM() ([]byte, error) {
	data, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}
	plain, err := decryptDPAPI(data)
	if err != nil {
		return nil, fmt.Errorf("DPAPI decrypt: %w", err)
	}
	return plain, nil
}

func saveClientCert(certPEM string) error {
	return os.WriteFile(clientCertPath, []byte(certPEM), 0644)
}

func hasClientCert() bool {
	if _, err := os.Stat(clientKeyPath); err != nil {
		return false
	}
	if _, err := os.Stat(clientCertPath); err != nil {
		return false
	}
	return true
}

// loadClientCertificate loads the stored cert+key pair as a tls.Certificate
// ready to attach to a tls.Config's Certificates field. Returns
// (cert, false, nil) if no client cert has been issued yet — callers should
// treat that as "proceed without one", not an error, since mTLS may simply
// not be enabled server-side.
func loadClientCertificate() (cert tls.Certificate, ok bool, err error) {
	if !hasClientCert() {
		return tls.Certificate{}, false, nil
	}
	keyPEM, err := loadClientKeyPEM()
	if err != nil {
		return tls.Certificate{}, false, err
	}
	certPEM, err := os.ReadFile(clientCertPath)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("read client cert: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("parse client cert/key pair: %w", err)
	}
	return tlsCert, true, nil
}

// clientCertificateNeedsRenewal keeps short-lived device identities fresh.
// Missing, malformed and expired certificates all request a replacement; the
// authenticated API key still lets the endpoint recover without reinstalling.
func clientCertificateNeedsRenewal(within time.Duration) bool {
	data, err := os.ReadFile(clientCertPath)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || time.Until(cert.NotAfter) <= within {
		return true
	}
	// Validate that an interrupted rotation did not leave a certificate and
	// DPAPI-protected private key from different key pairs. Treat any key load
	// or pair error as recoverable through authenticated renewal.
	keyPEM, err := loadClientKeyPEM()
	if err != nil {
		return true
	}
	_, err = tls.X509KeyPair(data, keyPEM)
	return err != nil
}

// csrFromStoredClientKey proves continuity of the device-held key during
// renewal. The private key remains DPAPI protected and is never transmitted.
func csrFromStoredClientKey(endpointHint string) ([]byte, error) {
	keyPEM, err := loadClientKeyPEM()
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("stored client key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse stored client key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("stored client key has an unsupported type")
	}
	request := x509.CertificateRequest{Subject: pkix.Name{CommonName: endpointHint}}
	der, err := x509.CreateCertificateRequest(rand.Reader, &request, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
