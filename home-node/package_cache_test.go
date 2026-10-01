package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPackageCacheVerifiedEncryptedReuse(t *testing.T) {
	setupBackupTest(t)
	cfg.PackageCacheMaxBytes = 1024 * 1024
	previous := packageCacheHTTPClient
	t.Cleanup(func() { packageCacheHTTPClient = previous })
	data := []byte("verified private installer")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/home-node/packages/app" || r.Header.Get("X-Warden-Home-Key") != cfg.NodeKey {
			t.Error("wrong source/auth")
		}
		w.Write(data)
	}))
	defer server.Close()
	cfg.WardenURL = server.URL
	cfg.NodeKey = "test-node-key"
	packageCacheHTTPClient = server.Client()
	root, err := packageCacheRoot()
	if err != nil {
		t.Fatal(err)
	}
	g := grant{AppID: "app", PackageSHA256: sha, MaxFileBytes: int64(len(data))}
	path, err := fetchCachedPackage(root, g)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, data) {
		t.Fatal("cache plaintext", err)
	}
	if _, err = fetchCachedPackage(root, g); err != nil || calls != 1 {
		t.Fatal("cache did not reuse verified bytes", err, calls)
	}
	bad := g
	bad.PackageSHA256 = strings.Repeat("b", 64)
	if _, err = fetchCachedPackage(root, bad); err == nil {
		t.Fatal("wrong source hash accepted")
	}
	if _, err = os.Stat(filepath.Join(root, bad.PackageSHA256+".blob")); !os.IsNotExist(err) {
		t.Fatal("invalid cache published")
	}
	raw[len(raw)-1] ^= 1
	os.WriteFile(path, raw, 0600)
	if _, err = fetchCachedPackage(root, g); err == nil {
		t.Fatal("tampered cache served")
	}
}
func TestPackageGrantAudienceNodeAndDeviceCertificate(t *testing.T) {
	setupBackupTest(t)
	private := configureTestCrypto(t)
	sha := strings.Repeat("a", 64)
	cfg.ClientCA = "test-ca"
	uri, _ := url.Parse("spiffe://warden/endpoint/tenant/device")
	request := httptest.NewRequest("GET", "https://home/v1/package?sha256="+sha, nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{uri}}}}
	g := grant{Audience: "warden-package-cache", CompanyID: "tenant", EndpointID: "device", NodeID: cfg.NodeID, AppID: "app", PackageSHA256: sha, Prefix: "packages/" + sha, Permissions: []string{"package"}, MaxFileBytes: 100, IssuedAt: time.Now().Unix() - 1, ExpiresAt: time.Now().Unix() + 900, Nonce: "cache-test"}
	sign := func(value grant) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, raw))
	}
	if _, err := verifyGrant(request, sign(g), g.Prefix, "package"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []grant{func() grant { v := g; v.NodeID = "other"; return v }(), func() grant { v := g; v.EndpointID = "other"; return v }(), func() grant { v := g; v.CompanyID = "other"; return v }(), func() grant { v := g; v.Audience = "unknown"; return v }()} {
		if _, err := verifyGrant(request, sign(bad), g.Prefix, "package"); err == nil {
			t.Fatal("mis-scoped package grant accepted")
		}
	}
	if _, err := verifyGrant(request, sign(g), g.Prefix, "read"); err == nil {
		t.Fatal("package token granted Home read access")
	}
	if _, err := verifyGrant(request, sign(g), "packages/"+strings.Repeat("b", 64), "package"); err == nil {
		t.Fatal("other digest granted")
	}
}

func TestPackageCacheQuotaReductionAndUnknownFiles(t *testing.T) {
	setupBackupTest(t)
	root, err := packageCacheRoot()
	if err != nil {
		t.Fatal(err)
	}
	cfg.PackageCacheMaxBytes = 100
	path := filepath.Join(root, strings.Repeat("a", 64)+".blob")
	os.WriteFile(path, make([]byte, 200), 0600)
	if err = reserveCacheSpace(root, 50); err != nil {
		t.Fatal("quota reduction could not evict", err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("cache not evicted")
	}
	os.WriteFile(filepath.Join(root, "user-document.txt"), []byte("keep"), 0600)
	if err = reserveCacheSpace(root, 50); err == nil {
		t.Fatal("unknown cache object silently removed")
	}
	if _, err = os.Stat(filepath.Join(root, "user-document.txt")); err != nil {
		t.Fatal("user file removed")
	}
}
