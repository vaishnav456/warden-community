package main

import (
 "crypto"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/pem"
 "fmt"
 "net/http"
)

func addDeviceRequestProof(request *http.Request, body []byte) error {
 _, present, err := loadClientCertificate()
 if err != nil { return err }
 if !present { return nil }
 var nonce [16]byte
 if _, err := rand.Read(nonce[:]); err != nil { return err }
 timestamp := fmt.Sprint(trustedCommandUnix())
 nonceHex := hex.EncodeToString(nonce[:])
 target := request.URL.Path
 if request.URL.RawQuery != "" { target += "?" + request.URL.RawQuery }
 digest := sha256.Sum256(body)
 message := fmt.Sprintf("warden-request-v1|%s|%s|%s|%s|%s|%s", getConfig().EndpointID, request.Method, target, timestamp, nonceHex, hex.EncodeToString(digest[:]))
 certificate, signature, err := signWithDeviceKey([]byte(message))
 if err != nil { return err }
 request.Header.Set("X-Warden-Device-Time", timestamp)
 request.Header.Set("X-Warden-Device-Nonce", nonceHex)
 request.Header.Set("X-Warden-Device-Certificate", base64.StdEncoding.EncodeToString([]byte(certificate)))
 request.Header.Set("X-Warden-Device-Signature", signature)
 return nil
}

func signWithDeviceKey(message []byte) (string, string, error) {
 certificate, ok, err := loadClientCertificate()
 if err != nil || !ok || len(certificate.Certificate) == 0 { return "", "", fmt.Errorf("device identity unavailable") }
 signer, ok := certificate.PrivateKey.(crypto.Signer)
 if !ok { return "", "", fmt.Errorf("device signing key unavailable") }
 digest := sha256.Sum256(message)
 signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
 if err != nil { return "", "", fmt.Errorf("device proof signing failed") }
 publicPEM := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:certificate.Certificate[0]})
 return string(publicPEM), base64.StdEncoding.EncodeToString(signature), nil
}
