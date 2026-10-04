package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

const heartbeatPath = "/api/agent/heartbeat"

var buildHeartbeatEncryption string

type heartbeatCryptoSession struct {
	public                       []byte
	serverUnix                   int64
	obtained                     time.Time
	endpoint, server, signingKey string
}

var heartbeatCryptoMu sync.Mutex
var heartbeatCryptoCached heartbeatCryptoSession

func heartbeatEncryptionRequired() bool {
	return getConfig().HeartbeatEncryptionRequired || buildHeartbeatEncryption == "true"
}
func verifyHeartbeatDescriptor(raw []byte, signingKey, endpoint, challenge string) (heartbeatCryptoSession, error) {
	var proof map[string]string
	if err := json.Unmarshal(raw, &proof); err != nil {
		return heartbeatCryptoSession{}, fmt.Errorf("invalid heartbeat key descriptor")
	}
	sig, err := base64.StdEncoding.DecodeString(proof["signature"])
	if err != nil {
		return heartbeatCryptoSession{}, fmt.Errorf("invalid heartbeat key signature")
	}
	delete(proof, "signature")
	if len(proof) != 5 || proof["version"] != "1" || proof["endpoint_id"] != endpoint || proof["challenge"] != challenge {
		return heartbeatCryptoSession{}, fmt.Errorf("heartbeat key binding mismatch")
	}
	canonical, err := json.Marshal(proof)
	if err != nil {
		return heartbeatCryptoSession{}, err
	}
	pub, err := loadServerPubkey(signingKey)
	if err != nil || !ed25519.Verify(pub, canonical, sig) {
		return heartbeatCryptoSession{}, fmt.Errorf("untrusted heartbeat encryption key")
	}
	encryptionPub, err := base64.StdEncoding.DecodeString(proof["public_key"])
	if err != nil || len(encryptionPub) != 32 {
		return heartbeatCryptoSession{}, fmt.Errorf("invalid heartbeat encryption key")
	}
	if _, err = ecdh.X25519().NewPublicKey(encryptionPub); err != nil {
		return heartbeatCryptoSession{}, err
	}
	unix, err := strconv.ParseInt(proof["server_time"], 10, 64)
	if err != nil || unix <= 0 {
		return heartbeatCryptoSession{}, fmt.Errorf("invalid signed server time")
	}
	return heartbeatCryptoSession{public: encryptionPub, serverUnix: unix, obtained: time.Now(), endpoint: endpoint, signingKey: signingKey}, nil
}
func heartbeatSession() (heartbeatCryptoSession, error) {
	heartbeatCryptoMu.Lock()
	defer heartbeatCryptoMu.Unlock()
	c := getConfig()
	cached := heartbeatCryptoCached
	if cached.endpoint == c.EndpointID && cached.server == serverURL() && cached.signingKey == c.ServerEd25519Pubkey && len(cached.public) == 32 && time.Since(cached.obtained) < 2*time.Minute {
		return cached, nil
	}
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		return heartbeatCryptoSession{}, err
	}
	challenge := base64.StdEncoding.EncodeToString(challengeBytes)
	raw, err := apiPostRaw("/api/agent/heartbeat/crypto", map[string]interface{}{"challenge": challenge}, true, heartbeatTimeoutSec)
	if err != nil {
		return heartbeatCryptoSession{}, fmt.Errorf("heartbeat encryption negotiation failed: %w", err)
	}
	session, err := verifyHeartbeatDescriptor(raw, c.ServerEd25519Pubkey, c.EndpointID, challenge)
	if err != nil {
		return heartbeatCryptoSession{}, err
	}
	session.server = serverURL()
	heartbeatCryptoCached = session
	return session, nil
}
func invalidateHeartbeatSession() {
	heartbeatCryptoMu.Lock()
	heartbeatCryptoCached = heartbeatCryptoSession{}
	heartbeatCryptoMu.Unlock()
}
func heartbeatAAD(endpoint, key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return []byte("warden-heartbeat-v1|POST|" + heartbeatPath + "|" + endpoint + "|" + hex.EncodeToString(hash[:]))
}

type heartbeatMessage struct {
	DeviceCertificate string `json:"device_certificate,omitempty"`
	DeviceSignature string `json:"device_signature,omitempty"`
	Version      int    `json:"version"`
	EphemeralKey string `json:"ephemeral_key,omitempty"`
	RequestNonce string `json:"request_nonce,omitempty"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}
type heartbeatReplyKey struct {
	key     []byte
	nonce   string
	context []byte
}

func heartbeatGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func sealHeartbeat(body map[string]interface{}, session heartbeatCryptoSession, endpoint, key string) ([]byte, heartbeatReplyKey, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, heartbeatReplyKey{}, err
	}
	public, err := ecdh.X25519().NewPublicKey(session.public)
	if err != nil {
		return nil, heartbeatReplyKey{}, err
	}
	shared, err := ephemeral.ECDH(public)
	if err != nil {
		return nil, heartbeatReplyKey{}, err
	}
	context := heartbeatAAD(endpoint, key)
	keys, err := hkdf.Key(sha256.New, shared, nil, string(context), 64)
	if err != nil {
		return nil, heartbeatReplyKey{}, err
	}
	plain, err := json.Marshal(map[string]interface{}{"issued_at": session.serverUnix + int64(time.Since(session.obtained)/time.Second), "body": body})
	if err != nil || len(plain) > 2*1024*1024-16 {
		return nil, heartbeatReplyKey{}, fmt.Errorf("invalid heartbeat body size")
	}
	aead, err := heartbeatGCM(keys[:32])
	if err != nil {
		return nil, heartbeatReplyKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, heartbeatReplyKey{}, err
	}
	nonceString := base64.StdEncoding.EncodeToString(nonce)
	ciphertext := aead.Seal(nil, nonce, plain, append(append([]byte{}, context...), []byte("|request")...))
	message := heartbeatMessage{Version: 1, EphemeralKey: base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()), Nonce: nonceString, Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}
	raw, err := json.Marshal(message)
	return raw, heartbeatReplyKey{key: keys[32:], nonce: nonceString, context: context}, err
}
func openHeartbeatReply(raw []byte, reply heartbeatReplyKey, status int) ([]byte, error) {
	var envelope heartbeatMessage
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Version != 1 || envelope.RequestNonce != reply.nonce {
		return nil, fmt.Errorf("missing or mismatched encrypted heartbeat response")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, fmt.Errorf("invalid heartbeat response nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) > 4*1024*1024 {
		return nil, fmt.Errorf("invalid heartbeat response size")
	}
	aead, err := heartbeatGCM(reply.key)
	if err != nil {
		return nil, err
	}
	context := append(append([]byte{}, reply.context...), []byte(fmt.Sprintf("|response|%s|%d", reply.nonce, status))...)
	plaintext, err := aead.Open(nil, nonce, ciphertext, context)
	if err != nil {
		return nil, fmt.Errorf("heartbeat response authentication failed")
	}
	return plaintext, nil
}
