package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type certificateResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	CABundlePEM    string `json:"ca_bundle_pem"`
	ExpiresAt      string `json:"expires_at"`
}

func loadServingCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("TLS certificate contains no leaf certificate")
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse TLS leaf certificate: %w", err)
	}
	return &cert, nil
}

func refreshServingCertificate(state *atomic.Pointer[tls.Certificate], certPath, keyPath string) (bool, error) {
	candidate, err := loadServingCertificate(certPath, keyPath)
	if err != nil {
		return false, err
	}
	current := state.Load()
	if current != nil && bytes.Equal(current.Certificate[0], candidate.Certificate[0]) {
		return false, nil
	}
	state.Store(candidate)
	return true, nil
}

func watchServingCertificate(certPath, keyPath string) (*atomic.Pointer[tls.Certificate], error) {
	initial, err := loadServingCertificate(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	state := &atomic.Pointer[tls.Certificate]{}
	state.Store(initial)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			changed, err := refreshServingCertificate(state, certPath, keyPath)
			if err != nil {
				// ACME clients commonly replace the certificate and key in two
				// filesystem operations. Keep serving the last valid pair and try
				// again instead of causing an outage during that short window.
				log.Printf("TLS certificate reload deferred: %v", err)
				continue
			}
			if !changed {
				continue
			}
			candidate := state.Load()
			log.Printf("TLS certificate renewed and reloaded; valid until %s", candidate.Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}()
	return state, nil
}

func nodeCertificateNeedsRenewal(within time.Duration) bool {
	raw, err := os.ReadFile(cfg.TLSCert)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || time.Until(cert.NotAfter) <= within {
		return true
	}
	for _, path := range []string{cfg.TLSKey, cfg.ClientCA, cfg.ClientCert, cfg.ClientKey} {
		if path == "" {
			return true
		}
		if _, err := os.Stat(path); err != nil {
			return true
		}
	}
	return false
}

func ensureNodeCertificate(configPath string, within time.Duration) error {
	if !nodeCertificateNeedsRenewal(within) {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Warden Home " + cfg.NodeID},
	}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, _ := json.Marshal(map[string]string{"node_id": cfg.NodeID, "csr_pem": string(csrPEM)})
	request, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(cfg.WardenURL, "/")+"/api/home-node/certificate", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Warden-Home-Key", cfg.NodeKey)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("certificate enrollment redirect refused")
	}}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("certificate enrollment returned HTTP %d", response.StatusCode)
	}
	var issued certificateResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(&issued); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := tls.X509KeyPair([]byte(issued.CertificatePEM), keyPEM); err != nil {
		return fmt.Errorf("issued certificate does not match local key: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(issued.CABundlePEM)) {
		return errors.New("issued CA bundle is invalid")
	}
	directory := filepath.Dir(configPath)
	keyPath := filepath.Join(directory, "warden-home-device.key.pem")
	certPath := filepath.Join(directory, "warden-home-device.crt.pem")
	caPath := filepath.Join(directory, "warden-device-ca.crt.pem")
	if err := atomicWrite(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := atomicWrite(certPath, []byte(issued.CertificatePEM), 0644); err != nil {
		return err
	}
	if err := atomicWrite(caPath, []byte(issued.CABundlePEM), 0644); err != nil {
		return err
	}
	cfg.TLSKey, cfg.TLSCert = keyPath, certPath
	cfg.ClientKey, cfg.ClientCert, cfg.ClientCA = keyPath, certPath, caPath
	updated, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(configPath, append(updated, '\n'), 0600); err != nil {
		return err
	}
	log.Printf("Warden Home device certificate installed; expires %s", issued.ExpiresAt)
	return nil
}

func tlsClientForPeer(p peer) (*http.Client, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(p.CACertificate) != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(p.CACertificate)) {
			return nil, errors.New("invalid peer private CA")
		}
		t.RootCAs = roots
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load current node client certificate: %w", err)
		}
		t.Certificates = []tls.Certificate{certificate}
	}
	if strings.TrimSpace(p.TLSFingerprint) != "" {
		normalized := strings.ToLower(strings.ReplaceAll(p.TLSFingerprint, ":", ""))
		if len(normalized) != 64 {
			return nil, errors.New("invalid peer pin")
		}
		t.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != normalized {
				return errors.New("peer TLS pin mismatch")
			}
			return nil
		}
	}
	transport := &http.Transport{TLSClientConfig: t}
	if p.ConnectionMode == "p2p" {
		transport = newHomeP2PTLSTransport(t, func() (net.Conn, error) {
			return dialNodeP2P(p)
		})
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("redirect refused") }}, nil
}
