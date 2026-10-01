package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestServingCertificate(t *testing.T, dir string, serial int64) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "home.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"home.test"},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func configureTestCrypto(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub = private.Public().(ed25519.PublicKey)
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ = cipher.NewGCM(block)
	cfg.NodeID = "node-a"
	cfg.ClientCA = ""
	return private
}

func testGrantWithLimits(t *testing.T, private ed25519.PrivateKey, prefix string, maxFileBytes, quotaBytes int64) string {
	t.Helper()
	payload := grant{Audience: "warden-home-node", CompanyID: "tenant-a", EndpointID: "endpoint-a",
		IdentityID: "identity-a", SpaceID: "space-a", NodeID: "node-a", Prefix: prefix,
		Permissions: []string{"read", "write", "delete"}, MaxFileBytes: maxFileBytes, QuotaBytes: quotaBytes,
		IssuedAt: time.Now().Unix() - 1, ExpiresAt: time.Now().Unix() + 300, Nonce: "nonce-a"}
	raw, _ := json.Marshal(payload)
	sig := ed25519.Sign(private, raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testGrant(t *testing.T, private ed25519.PrivateKey, prefix string) string {
	return testGrantWithLimits(t, private, prefix, 512*1024*1024, 0)
}

func TestEncryptedStreamRoundTrip(t *testing.T) {
	configureTestCrypto(t)
	plain := bytes.Repeat([]byte("warden-home"), 500000)
	var encrypted bytes.Buffer
	if _, err := encryptStream(&encrypted, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes(), []byte("warden-home")) {
		t.Fatal("plaintext leaked into encrypted file")
	}
	var decoded bytes.Buffer
	if err := decryptStream(&decoded, &encrypted); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, decoded.Bytes()) {
		t.Fatal("round trip changed file")
	}
}

func TestEncryptedStreamBindsPathAndRejectsTruncation(t *testing.T) {
	configureTestCrypto(t)
	plain := bytes.Repeat([]byte("bound-content"), 1000)
	var encrypted bytes.Buffer
	if _, err := encryptStreamForPath(&encrypted, bytes.NewReader(plain), "home/alice/document.txt"); err != nil {
		t.Fatal(err)
	}
	if err := decryptStreamForPath(io.Discard, bytes.NewReader(encrypted.Bytes()), "home/bob/document.txt"); err == nil {
		t.Fatal("ciphertext transplanted to another path was accepted")
	}
	truncated := encrypted.Bytes()[:encrypted.Len()-1]
	if err := decryptStreamForPath(io.Discard, bytes.NewReader(truncated), "home/alice/document.txt"); err == nil {
		t.Fatal("truncated encrypted file was accepted")
	}
}

func TestEncryptedMetadataRejectsQuotaTampering(t *testing.T) {
	configureTestCrypto(t)
	cfg.Root = t.TempDir()
	if err := writeFile("homes/alice/document.txt", bytes.NewReader([]byte("secret")), 123, 1024); err != nil {
		t.Fatal(err)
	}
	_, metaPath, err := pathsFor("homes/alice/document.txt")
	if err != nil {
		t.Fatal(err)
	}
	m := loadMeta(metaPath)
	if !m.Valid || m.Size != 6 {
		t.Fatalf("valid metadata rejected: %+v", m)
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	var changed map[string]interface{}
	if err := json.Unmarshal(raw, &changed); err != nil {
		t.Fatal(err)
	}
	changed["Size"] = float64(0)
	raw, _ = json.Marshal(changed)
	if err := os.WriteFile(metaPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if loadMeta(metaPath).Valid {
		t.Fatal("tampered quota metadata was accepted")
	}
}

func TestReplicationReadinessSurvivesRestart(t *testing.T) {
	cfg.Root = t.TempDir()
	replicationMu.Lock()
	replicationOK = map[string]int64{}
	replicationMu.Unlock()
	first, err := recordReplicationSuccess("space-a")
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first successful replication was not identified")
	}
	replicationMu.Lock()
	replicationOK = map[string]int64{}
	replicationMu.Unlock()
	if err := loadReplicationState(); err != nil {
		t.Fatal(err)
	}
	replicationMu.Lock()
	syncedAt := replicationOK["space-a"]
	replicationMu.Unlock()
	if syncedAt <= 0 {
		t.Fatal("durable replication readiness was not restored")
	}
}

func TestFileAPIEnforcesPerFileAndSpaceQuota(t *testing.T) {
	private := configureTestCrypto(t)
	cfg.Root = t.TempDir()
	path := "/v1/file?path=homes%2Fidentity-a%2FDocuments%2Ftest.txt"

	tooLarge := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte("12345")))
	tooLarge.Header.Set("Authorization", "Bearer "+testGrantWithLimits(t, private, "homes/identity-a", 4, 100))
	tooLargeResult := httptest.NewRecorder()
	handleFile(tooLargeResult, tooLarge)
	if tooLargeResult.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("per-file limit returned %d", tooLargeResult.Code)
	}

	first := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte("123456")))
	first.Header.Set("Authorization", "Bearer "+testGrantWithLimits(t, private, "homes/identity-a", 100, 8))
	firstResult := httptest.NewRecorder()
	handleFile(firstResult, first)
	if firstResult.Code != http.StatusNoContent {
		t.Fatalf("initial quota write returned %d: %s", firstResult.Code, firstResult.Body.String())
	}

	second := httptest.NewRequest(http.MethodPut, "/v1/file?path=homes%2Fidentity-a%2FDocuments%2Fsecond.txt", bytes.NewReader([]byte("abc")))
	second.Header.Set("Authorization", "Bearer "+testGrantWithLimits(t, private, "homes/identity-a", 100, 8))
	secondResult := httptest.NewRecorder()
	handleFile(secondResult, second)
	if secondResult.Code != http.StatusInsufficientStorage {
		t.Fatalf("space quota returned %d", secondResult.Code)
	}
}

func TestServingCertificateCanReloadAfterRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestServingCertificate(t, dir, 1)
	state, err := watchServingCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Load().Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("initial serving certificate was not loaded")
	}
	writeTestServingCertificate(t, dir, 2)
	changed, err := refreshServingCertificate(state, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || state.Load().Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("renewed serving certificate was not reloaded")
	}
}

func TestSharedStorageLockSerializesWriters(t *testing.T) {
	cfg.Root = t.TempDir()
	cfg.NodeID = "node-a"
	cfg.StorageClusterID = "cluster-a"
	release, err := acquireSpaceLock("shared/finance")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("cluster-a\x00shared/finance"))
	lockPath := filepath.Join(cfg.Root, ".warden-locks", hex.EncodeToString(digest[:]))
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatal("shared lock was not created")
	}
	release()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("shared lock was not released")
	}
	cfg.StorageClusterID = ""
}

func TestGrantCannotEscapePrefixOrTargetAnotherNode(t *testing.T) {
	private := configureTestCrypto(t)
	token := testGrant(t, private, "homes/identity-a")
	if _, err := verifyGrant(nil, token, "homes/identity-a/Documents/a.txt", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyGrant(nil, token, "homes/identity-b/a.txt", "read"); err == nil {
		t.Fatal("cross-prefix access accepted")
	}
	cfg.NodeID = "node-b"
	if _, err := verifyGrant(nil, token, "homes/identity-a/a.txt", "read"); err == nil {
		t.Fatal("cross-node grant accepted")
	}
}

func TestGrantMustMatchVerifiedDeviceCertificate(t *testing.T) {
	private := configureTestCrypto(t)
	cfg.ClientCA = "warden-device-ca.pem"
	t.Cleanup(func() { cfg.ClientCA = "" })
	token := testGrant(t, private, "homes/identity-a")
	matching, _ := url.Parse("spiffe://warden/endpoint/tenant-a/endpoint-a")
	request := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{matching}}}}}
	if _, err := verifyGrant(request, token, "homes/identity-a/a.txt", "read"); err != nil {
		t.Fatalf("matching device identity rejected: %v", err)
	}
	wrong, _ := url.Parse("spiffe://warden/endpoint/tenant-b/endpoint-a")
	request.TLS.PeerCertificates[0].URIs = []*url.URL{wrong}
	if _, err := verifyGrant(request, token, "homes/identity-a/a.txt", "read"); err == nil {
		t.Fatal("cross-organization device certificate accepted")
	}
}

func TestFileAPIEncryptedPutListGetDelete(t *testing.T) {
	private := configureTestCrypto(t)
	cfg.Root = t.TempDir()
	token := testGrant(t, private, "homes/identity-a")
	plain := []byte("private tenant document")

	put := httptest.NewRequest(http.MethodPut, "/v1/file?path=homes%2Fidentity-a%2FDocuments%2Ftest.txt", bytes.NewReader(plain))
	put.Header.Set("Authorization", "Bearer "+token)
	put.Header.Set("X-Warden-Mtime", time.Unix(1700000000, 0).UTC().Format(time.RFC3339))
	putResult := httptest.NewRecorder()
	handleFile(putResult, put)
	if putResult.Code != http.StatusNoContent {
		t.Fatalf("PUT status %d: %s", putResult.Code, putResult.Body.String())
	}

	stored, err := os.ReadFile(filepath.Join(cfg.Root, "homes", "identity-a", "Documents", "test.txt.whome"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, plain) {
		t.Fatal("stored file contains plaintext")
	}

	list := httptest.NewRequest(http.MethodGet, "/v1/list?path=homes%2Fidentity-a", nil)
	list.Header.Set("Authorization", "Bearer "+token)
	listResult := httptest.NewRecorder()
	handleList(listResult, list)
	if listResult.Code != http.StatusOK {
		t.Fatalf("LIST status %d", listResult.Code)
	}
	var entries []fileEntry
	if err := json.Unmarshal(listResult.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "homes/identity-a/Documents/test.txt" {
		t.Fatalf("unexpected list: %#v", entries)
	}

	get := httptest.NewRequest(http.MethodGet, "/v1/file?path=homes%2Fidentity-a%2FDocuments%2Ftest.txt", nil)
	get.Header.Set("Authorization", "Bearer "+token)
	getResult := httptest.NewRecorder()
	handleFile(getResult, get)
	got, _ := io.ReadAll(getResult.Result().Body)
	if getResult.Code != http.StatusOK || !bytes.Equal(got, plain) {
		t.Fatalf("GET status %d body %q", getResult.Code, got)
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/file?path=homes%2Fidentity-a%2FDocuments%2Ftest.txt", nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+token)
	deleteResult := httptest.NewRecorder()
	handleFile(deleteResult, deleteRequest)
	if deleteResult.Code != http.StatusNoContent {
		t.Fatalf("DELETE status %d", deleteResult.Code)
	}
	if _, err := os.Stat(filepath.Join(cfg.Root, "homes", "identity-a", "Documents", "test.txt.whome")); !os.IsNotExist(err) {
		t.Fatal("deleted encrypted contents still present", err)
	}
	getAfterDelete := httptest.NewRecorder()
	handleFile(getAfterDelete, get)
	if getAfterDelete.Code != http.StatusNotFound {
		t.Fatal("deleted file is still served")
	}
	deleted, err := readHomeDeletion("homes/identity-a/Documents/test.txt")
	if err != nil || deleted == nil {
		t.Fatal("deletion record missing", err)
	}
}

func TestEncryptedBackupRequiresOriginalRecoveryKey(t *testing.T) {
	configureTestCrypto(t)
	ciphertext := &bytes.Buffer{}
	plain := []byte("tenant recovery data")
	if _, err := encryptStream(ciphertext, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err = cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if err := decryptStream(io.Discard, bytes.NewReader(ciphertext.Bytes())); err == nil {
		t.Fatal("encrypted backup decrypted with the wrong recovery key")
	}
}
