package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func signHeartbeatDeviceProof(raw []byte, context []byte) ([]byte, error) {
	var envelope heartbeatMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{envelope.EphemeralKey, envelope.Nonce, envelope.Ciphertext}, "|")))
	message := append(append([]byte{}, context...), []byte("|device-proof|"+hex.EncodeToString(digest[:]))...)
	cert, signature, err := signWithDeviceKey(message)
	if err != nil {
		return nil, err
	}
	envelope.DeviceCertificate, envelope.DeviceSignature = cert, signature
	return json.Marshal(envelope)
}
