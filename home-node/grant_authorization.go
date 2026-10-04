package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type grant struct {
	AppID         string   `json:"app_id"`
	PackageSHA256 string   `json:"package_sha256"`
	Audience      string   `json:"aud"`
	CompanyID     string   `json:"company_id"`
	EndpointID    string   `json:"endpoint_id"`
	SourceNodeID  string   `json:"source_node_id"`
	IdentityID    string   `json:"identity_id"`
	SpaceID       string   `json:"space_id"`
	NodeID        string   `json:"node_id"`
	Prefix        string   `json:"prefix"`
	Permissions   []string `json:"permissions"`
	MaxFileBytes  int64    `json:"max_file_bytes"`
	QuotaBytes    int64    `json:"quota_bytes"`
	HistoryDays   int      `json:"history_days"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	Nonce         string   `json:"nonce"`
}

func hasPermission(g grant, wanted string) bool {
	for _, p := range g.Permissions {
		if p == wanted {
			return true
		}
	}
	return false
}

func verifyPeerCertificate(r *http.Request, g grant) error {
	if cfg.ClientCA == "" {
		return nil
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("verified device certificate is required")
	}
	kind, identity := "endpoint", g.EndpointID
	if g.Audience == "warden-home-replication" {
		kind, identity = "home-node", g.SourceNodeID
	}
	expected := fmt.Sprintf("spiffe://warden/%s/%s/%s", kind, g.CompanyID, identity)
	for _, uri := range r.TLS.PeerCertificates[0].URIs {
		if uri.String() == expected {
			return nil
		}
	}
	return errors.New("device certificate does not match the signed grant")
}

func verifyGrant(r *http.Request, raw, requestPath, permission string) (grant, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return grant{}, errors.New("invalid grant")
	}
	payload, err := decodeB64(parts[0])
	if err != nil {
		return grant{}, err
	}
	sig, err := decodeB64(parts[1])
	if err != nil {
		return grant{}, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return grant{}, errors.New("invalid signature")
	}
	var g grant
	if err := json.Unmarshal(payload, &g); err != nil {
		return grant{}, err
	}
	now := time.Now().Unix()
	if g.NodeID != cfg.NodeID || g.ExpiresAt < now || g.IssuedAt > now+300 || g.ExpiresAt-g.IssuedAt > 3600 || g.Nonce == "" {
		return grant{}, errors.New("expired or mis-scoped grant")
	}
	if g.Audience != "warden-home-node" && g.Audience != "warden-home-replication" && !(permission == "package" && g.Audience == "warden-package-cache") {
		return grant{}, errors.New("invalid audience")
	}
	if err := verifyPeerCertificate(r, g); err != nil {
		return grant{}, err
	}
	if !hasPermission(g, permission) && !(permission == "read" && hasPermission(g, "replicate")) {
		return grant{}, errors.New("permission denied")
	}
	p, err := cleanRelative(requestPath)
	if err != nil {
		return grant{}, err
	}
	prefix, err := cleanRelative(g.Prefix)
	if err != nil {
		return grant{}, err
	}
	if p != prefix && !strings.HasPrefix(p, prefix+"/") {
		return grant{}, errors.New("path outside grant")
	}
	nonceMu.Lock()
	for n, expiry := range seenNonces {
		if expiry < now {
			delete(seenNonces, n)
		}
	}
	// A grant is reusable for a bounded sync session, so bind nonce to its
	// expiry rather than rejecting its second file request.
	seenNonces[g.Nonce] = g.ExpiresAt
	nonceMu.Unlock()
	return g, nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}
