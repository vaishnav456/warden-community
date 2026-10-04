package moduletrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Grant, Context, ed25519.PrivateKey, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	file := []byte("verified development-only module fixture")
	digest := sha256.Sum256(file)
	now := time.Unix(1800000000, 0)
	grant := Grant{Schema: 1, ModuleID: "helpdesk", TenantID: "11111111-1111-4111-8111-111111111111", EndpointID: "22222222-2222-4222-8222-222222222222", ReleaseID: "33333333-3333-4333-8333-333333333333", Sequence: 2, Version: "1.0.0", MinCoreVersion: "2.7.0", IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 120, DownloadURL: "https://warden-dev.example/api/agent/modules/helpdesk/package/33333333-3333-4333-8333-333333333333", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(file)), Entitled: true, AdminEnabled: true, Capabilities: []string{"helpdesk.tickets.read", "helpdesk.tickets.write"}}
	context := Context{PublicKey: public, TenantID: grant.TenantID, EndpointID: grant.EndpointID, ServerURL: "https://warden-dev.example", CoreVersion: "2.7.0", Now: now, InstalledSequence: 1}
	return grant, context, private, file
}
func signed(grant Grant, key ed25519.PrivateKey) []byte {
	payload, _ := json.Marshal(grant)
	raw, _ := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))})
	return raw
}
func TestVerifiedModulePackage(t *testing.T) {
	g, c, key, file := fixture(t)
	approved, err := Verify(signed(g, key), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := approved.VerifyPackage(bytes.NewReader(file)); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{append(file, 'x'), file[:len(file)-1], bytes.Repeat([]byte{'x'}, len(file))} {
		if approved.VerifyPackage(bytes.NewReader(data)) == nil {
			t.Fatal("modified module accepted")
		}
	}
	copy := approved.Grant()
	copy.Capabilities[0] = "remote.control"
	if approved.Grant().Capabilities[0] != "helpdesk.tickets.read" {
		t.Fatal("caller mutated verified capabilities")
	}
}
func TestModuleGrantsFailClosed(t *testing.T) {
	cases := map[string]func(*Grant){
		"subscription denied": func(g *Grant) { g.Entitled = false }, "admin disabled": func(g *Grant) { g.AdminEnabled = false },
		"wrong tenant": func(g *Grant) { g.TenantID = "44444444-4444-4444-8444-444444444444" }, "wrong endpoint": func(g *Grant) { g.EndpointID = "44444444-4444-4444-8444-444444444444" },
		"unknown module": func(g *Grant) { g.ModuleID = "vpn" }, "core is not optional": func(g *Grant) { g.ModuleID = "core" },
		"expired": func(g *Grant) { g.ExpiresAt = g.IssuedAt }, "future": func(g *Grant) { g.IssuedAt += 31 }, "long lease": func(g *Grant) { g.ExpiresAt += 300 },
		"rollback": func(g *Grant) { g.Sequence = 0 }, "incompatible core": func(g *Grant) { g.MinCoreVersion = "2.8.0" },
		"external URL": func(g *Grant) {
			g.DownloadURL = strings.Replace(g.DownloadURL, "warden-dev.example", "attacker.example", 1)
		},
		"URL credentials": func(g *Grant) { g.DownloadURL = strings.Replace(g.DownloadURL, "https://", "https://user@", 1) },
		"plaintext URL":   func(g *Grant) { g.DownloadURL = strings.Replace(g.DownloadURL, "https:", "http:", 1) },
		"token URL":       func(g *Grant) { g.DownloadURL += "?token=secret" }, "URL fragment": func(g *Grant) { g.DownloadURL += "#hidden" },
		"path traversal": func(g *Grant) { g.DownloadURL = strings.Replace(g.DownloadURL, "/package/", "/package/../", 1) },
		"huge package":   func(g *Grant) { g.SizeBytes = MaxPackageBytes + 1 }, "invalid hash": func(g *Grant) { g.SHA256 = "bad" },
		"privilege escalation": func(g *Grant) { g.Capabilities[1] = "remote.control" }, "extra capability": func(g *Grant) { g.Capabilities = append(g.Capabilities, "system.exec") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			g, c, key, _ := fixture(t)
			change(&g)
			if _, err := Verify(signed(g, key), c); err == nil {
				t.Fatal("unsafe grant accepted")
			}
		})
	}
}
func TestModuleSignatureAndSequence(t *testing.T) {
	g, c, key, _ := fixture(t)
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(signed(g, wrong), c); err == nil {
		t.Fatal("untrusted signer")
	}
	var envelope Envelope
	json.Unmarshal(signed(g, key), &envelope)
	envelope.Payload = base64.StdEncoding.EncodeToString([]byte(`{"module_id":"vpn"}`))
	raw, _ := json.Marshal(envelope)
	if _, err := Verify(raw, c); err == nil {
		t.Fatal("modified signed payload")
	}
	c.InstalledSequence = g.Sequence
	c.InstalledSHA256 = g.SHA256
	if _, err := Verify(signed(g, key), c); err != nil {
		t.Fatal("same verified release must be idempotent", err)
	}
	c.InstalledSHA256 = strings.Repeat("0", 64)
	if _, err := Verify(signed(g, key), c); err == nil {
		t.Fatal("same-sequence replacement accepted")
	}
}

func TestDuplicateManifestKeysRejected(t *testing.T) {
	g, c, key, _ := fixture(t)
	payload, _ := json.Marshal(g)
	for _, duplicate := range []string{`"admin_enabled":false,`, `"ADMIN_ENABLED":false,`} {
		ambiguous := append([]byte("{"+duplicate), payload[1:]...)
		raw, _ := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(ambiguous), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, ambiguous))})
		if _, err := Verify(raw, c); err == nil {
			t.Fatal("ambiguous signed grant accepted")
		}
	}
	raw := signed(g, key)
	for _, field := range []string{`"payload_b64":"",`, `"PAYLOAD_B64":"",`} {
		ambiguous := append([]byte("{"+field), raw[1:]...)
		if _, err := Verify(ambiguous, c); err == nil {
			t.Fatal("ambiguous envelope accepted")
		}
	}
}
