package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatPythonWireCompatibility(t *testing.T) {
	raw, err := os.ReadFile("testdata/heartbeat-crypto-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Descriptor json.RawMessage  `json:"descriptor"`
		SigningKey string           `json:"signing_key"`
		Request    heartbeatMessage `json:"request"`
		Response   json.RawMessage  `json:"response"`
		KeysHex    string           `json:"keys_hex"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	challenge := base64.StdEncoding.EncodeToString(make([]byte, 32))
	session, err := verifyHeartbeatDescriptor(fixture.Descriptor, fixture.SigningKey, "endpoint-a", challenge)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 32)
	}
	ephemeral, _ := ecdh.X25519().NewPrivateKey(seed)
	pub, _ := ecdh.X25519().NewPublicKey(session.public)
	shared, _ := ephemeral.ECDH(pub)
	context := heartbeatAAD("endpoint-a", "test-agent-key")
	keys, _ := hkdf.Key(sha256.New, shared, nil, string(context), 64)
	if hex.EncodeToString(keys) != fixture.KeysHex {
		t.Fatal("Python/Go key derivation mismatch")
	}
	aead, _ := heartbeatGCM(keys[:32])
	nonce, _ := base64.StdEncoding.DecodeString(fixture.Request.Nonce)
	cipher, _ := base64.StdEncoding.DecodeString(fixture.Request.Ciphertext)
	plain, err := aead.Open(nil, nonce, cipher, append(append([]byte{}, context...), []byte("|request")...))
	if err != nil || !strings.Contains(string(plain), "TEST-PC") {
		t.Fatal("Python request interoperability", err)
	}
	reply := heartbeatReplyKey{key: keys[32:], nonce: fixture.Request.Nonce, context: context}
	plain, err = openHeartbeatReply(fixture.Response, reply, 200)
	if err != nil || string(plain) != "{\"ok\":true}" {
		t.Fatal("Python response interoperability", err)
	}
}
func TestHeartbeatDescriptorSignatureAndBinding(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	proof := map[string]string{"version": "1", "endpoint_id": "endpoint-a", "challenge": "challenge-a", "public_key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "server_time": "2000000000"}
	canonical, _ := json.Marshal(proof)
	proof["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	raw, _ := json.Marshal(proof)
	key := base64.StdEncoding.EncodeToString(public)
	if _, err := verifyHeartbeatDescriptor(raw, key, "endpoint-a", "challenge-a"); err != nil {
		t.Fatal(err)
	}
	for _, binding := range [][2]string{{"endpoint-b", "challenge-a"}, {"endpoint-a", "replay-challenge"}} {
		if _, err := verifyHeartbeatDescriptor(raw, key, binding[0], binding[1]); err == nil {
			t.Fatal("binding not verified")
		}
	}
	proof["server_time"] = "2000000001"
	raw, _ = json.Marshal(proof)
	if _, err := verifyHeartbeatDescriptor(raw, key, "endpoint-a", "challenge-a"); err == nil {
		t.Fatal("descriptor tamper accepted")
	}
}
func TestHeartbeatMessageRoundTripAndTamper(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	session := heartbeatCryptoSession{public: server.PublicKey().Bytes(), serverUnix: 2000000000, obtained: time.Now()}
	raw, reply, err := sealHeartbeat(map[string]interface{}{"hostname": "PRIVATE-PC", "cpu_pct": 32.5}, session, "endpoint-a", "agent-key")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE-PC") {
		t.Fatal("readable heartbeat")
	}
	var request heartbeatMessage
	if err = json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	ephemeral, _ := base64.StdEncoding.DecodeString(request.EphemeralKey)
	ephemeralPub, _ := ecdh.X25519().NewPublicKey(ephemeral)
	shared, _ := server.ECDH(ephemeralPub)
	context := heartbeatAAD("endpoint-a", "agent-key")
	keys, _ := hkdf.Key(sha256.New, shared, nil, string(context), 64)
	aead, _ := heartbeatGCM(keys[:32])
	nonce, _ := base64.StdEncoding.DecodeString(request.Nonce)
	ciphertext, _ := base64.StdEncoding.DecodeString(request.Ciphertext)
	plain, err := aead.Open(nil, nonce, ciphertext, append(context, []byte("|request")...))
	if err != nil || !strings.Contains(string(plain), "PRIVATE-PC") {
		t.Fatal("request round trip failed", err)
	}
	wrong := heartbeatAAD("endpoint-b", "agent-key")
	if _, err = aead.Open(nil, nonce, ciphertext, append(wrong, []byte("|request")...)); err == nil {
		t.Fatal("cross endpoint accepted")
	}
	responseAEAD, _ := heartbeatGCM(keys[32:])
	responseNonce := make([]byte, 12)
	rand.Read(responseNonce)
	responseContext := append(heartbeatAAD("endpoint-a", "agent-key"), []byte("|response|"+request.Nonce+"|200")...)
	sealed := responseAEAD.Seal(nil, responseNonce, []byte("{\"ok\":true}"), responseContext)
	response := heartbeatMessage{Version: 1, RequestNonce: request.Nonce, Nonce: base64.StdEncoding.EncodeToString(responseNonce), Ciphertext: base64.StdEncoding.EncodeToString(sealed)}
	responseRaw, _ := json.Marshal(response)
	decoded, err := openHeartbeatReply(responseRaw, reply, 200)
	if err != nil || string(decoded) != "{\"ok\":true}" {
		t.Fatal("response failed", err)
	}
	if _, err = openHeartbeatReply(responseRaw, reply, 500); err == nil {
		t.Fatal("HTTP status tamper accepted")
	}
	response.RequestNonce = "other-request"
	responseRaw, _ = json.Marshal(response)
	if _, err = openHeartbeatReply(responseRaw, reply, 200); err == nil {
		t.Fatal("response replay accepted")
	}
	if _, err = openHeartbeatReply([]byte("{\"ok\":true}"), reply, 200); err == nil {
		t.Fatal("plaintext downgrade accepted")
	}
}
func TestInstalledAgentIntegrityProofTrust(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	hash := strings.Repeat("a", 64)
	proof := map[string]string{"purpose": "warden-agent-integrity-v2", "endpoint_id": "endpoint-a", "agent_version": agentVersion, "sha256": hash, "challenge": "challenge-a", "installation_id": "installation-a", "device_cert_sha256": strings.Repeat("c", 64), "api_key_sha256": strings.Repeat("d", 64)}
	proof["measurement_sha256"] = agentIntegrityMeasurement(proof)
	canonical, _ := json.Marshal(proof)
	proof["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	raw, _ := json.Marshal(proof)
	key := base64.StdEncoding.EncodeToString(public)
	if err := verifyAgentIntegrityProof(raw, key, "endpoint-a", agentVersion, hash, "challenge-a"); err != nil {
		t.Fatal(err)
	}
	if err := verifyAgentIntegrityProof(raw, key, "endpoint-a", agentVersion, strings.Repeat("b", 64), "challenge-a"); err == nil {
		t.Fatal("modified installed binary accepted")
	}
	if err := verifyAgentIntegrityProof(raw, key, "endpoint-b", agentVersion, hash, "challenge-a"); err == nil {
		t.Fatal("cross-endpoint proof accepted")
	}
	proof["sha256"] = strings.Repeat("b", 64)
	raw, _ = json.Marshal(proof)
	if err := verifyAgentIntegrityProof(raw, key, "endpoint-a", agentVersion, proof["sha256"], "challenge-a"); err == nil {
		t.Fatal("manifest tamper accepted")
	}
}
