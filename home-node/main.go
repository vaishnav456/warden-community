// Warden Home Node stores tenant files without routing file contents through
// the Warden control plane. Every data request requires an offline-verifiable,
// short-lived Ed25519 grant scoped to a tenant, node, space and path prefix.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const magic = "WHOME1\x00" // legacy reader compatibility
const magicV2 = "WHOME2\x00"
const chunkSize = 4 * 1024 * 1024

type config struct {
	BackupRoot           string `json:"backup_root"`
	BackupMaxBytes       int64  `json:"backup_max_bytes"`
	BackupIntervalHours  int    `json:"backup_interval_hours"`
	PackageCacheMaxBytes int64  `json:"package_cache_max_bytes"`
	NodeID               string `json:"node_id"`
	NodeKey              string `json:"node_key"`
	WardenURL            string `json:"warden_url"`
	ServerPublicKey      string `json:"server_public_key"`
	Listen               string `json:"listen"`
	Root                 string `json:"root"`
	TLSCert              string `json:"tls_cert"`
	TLSKey               string `json:"tls_key"`
	ClientCA             string `json:"client_ca"`
	ClientCert           string `json:"client_cert"`
	ClientKey            string `json:"client_key"`
	EncryptionKey        string `json:"encryption_key"`
	PublicMode           bool   `json:"public_mode"`
	Replication          bool   `json:"replication"`
	StorageClusterID     string `json:"storage_cluster_id"`
}

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

type peer struct {
	SpaceID        string   `json:"space_id"`
	TargetNodeID   string   `json:"target_node_id"`
	ConnectionMode string   `json:"connection_mode"`
	P2PURL         string   `json:"p2p_url"`
	STUNURLs       []string `json:"stun_urls"`
	LocalURL       string   `json:"local_url"`
	PublicURL      string   `json:"public_url"`
	TLSFingerprint string   `json:"tls_fingerprint"`
	CACertificate  string   `json:"ca_certificate_pem"`
	Prefix         string   `json:"prefix"`
	Grant          string   `json:"grant"`
	MaxFileBytes   int64    `json:"max_file_bytes"`
	QuotaBytes     int64    `json:"quota_bytes"`
	HistoryDays    int      `json:"history_days"`
}

type heartbeatResponse struct {
	OK               bool           `json:"ok"`
	ServerPublicKey  string         `json:"server_public_key"`
	ReplicationPeers []peer         `json:"replication_peers"`
	Update           *managedUpdate `json:"update"`
}

type certificateResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	CABundlePEM    string `json:"ca_bundle_pem"`
	ExpiresAt      string `json:"expires_at"`
}

type fileEntry struct {
	Deleted bool   `json:"deleted,omitempty"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
	SHA256  string `json:"sha256,omitempty"`
	IsDir   bool   `json:"is_dir,omitempty"`
}

type metadata struct {
	Size    int64  `json:"Size"`
	ModTime int64  `json:"ModTime"`
	Auth    string `json:"Auth,omitempty"`
	SHA256  string `json:"SHA256,omitempty"`
	Valid   bool   `json:"-"`
	Exists  bool   `json:"-"`
}

var (
	cfg               config
	configPathInUse   string
	pub               ed25519.PublicKey
	aead              cipher.AEAD
	peerClientCert    tls.Certificate
	peerCertLoaded    bool
	encryptionKeyID   string
	nonceMu           sync.Mutex
	seenNonces        = map[string]int64{}
	storageMu         sync.Mutex
	replicationMu     sync.Mutex
	replicationOK     = map[string]int64{}
	replicationActive sync.Map
	replicationReady  = make(chan struct{}, 1)
)

var errFileTooLarge = errors.New("file too large")

func acquireSpaceLock(prefix string) (func(), error) {
	if strings.TrimSpace(cfg.StorageClusterID) == "" {
		return func() {}, nil
	}
	lockRoot := filepath.Join(cfg.Root, ".warden-locks")
	if err := os.MkdirAll(lockRoot, 0700); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(cfg.StorageClusterID + "\x00" + prefix))
	lockPath := filepath.Join(lockRoot, hex.EncodeToString(digest[:]))
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := os.Mkdir(lockPath, 0700); err == nil {
			_ = os.WriteFile(filepath.Join(lockPath, "owner"), []byte(cfg.NodeID), 0600)
			stopRefresh := make(chan struct{})
			go func() {
				ticker := time.NewTicker(time.Minute)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						now := time.Now()
						_ = os.Chtimes(lockPath, now, now)
					case <-stopRefresh:
						return
					}
				}
			}()
			return sync.OnceFunc(func() {
				close(stopRefresh)
				_ = os.RemoveAll(lockPath)
			}), nil
		} else if !os.IsExist(err) {
			return nil, err
		}
		if info, err := os.Stat(lockPath); err == nil && time.Since(info.ModTime()) > 15*time.Minute {
			_ = os.RemoveAll(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("shared storage is busy")
		}
		time.Sleep(100 * time.Millisecond)
	}
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

func decodeB64(s string) ([]byte, error) {
	if v, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return v, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func cleanRelative(value string) (string, error) {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	value = strings.TrimPrefix(value, "/")
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || filepath.IsAbs(clean) {
		return "", errors.New("invalid relative path")
	}
	return clean, nil
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

func pathsFor(rel string) (string, string, error) {
	clean, err := cleanRelative(rel)
	if err != nil {
		return "", "", err
	}
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return "", "", err
	}
	data := filepath.Join(root, filepath.FromSlash(clean)+".whome")
	full, err := filepath.Abs(data)
	if err != nil {
		return "", "", err
	}
	if full != root && !strings.HasPrefix(strings.ToLower(full), strings.ToLower(root+string(os.PathSeparator))) {
		return "", "", errors.New("path escape")
	}
	// Lexical containment is not enough when an attacker can place a symlink
	// below the storage root. Reject every existing symlink component,
	// including the final encrypted file, before opening it.
	relToRoot, err := filepath.Rel(root, full)
	if err != nil {
		return "", "", err
	}
	cursor := root
	for _, component := range strings.Split(relToRoot, string(os.PathSeparator)) {
		cursor = filepath.Join(cursor, component)
		info, statErr := os.Lstat(cursor)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				break
			}
			return "", "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("symlink paths are not permitted")
		}
	}
	return full, full + ".meta", nil
}

func encryptStream(dst io.Writer, src io.Reader) (int64, error) {
	return encryptStreamForPath(dst, src, "")
}

func streamAAD(rel string, fileID []byte, index, total uint64, manifest bool) []byte {
	kind := "chunk"
	if manifest {
		kind = "manifest"
	}
	return []byte(fmt.Sprintf("warden-home:v2:%s:%x:%s:%d:%d", rel, fileID, kind, index, total))
}

func encryptStreamForPath(dst io.Writer, src io.Reader, rel string) (int64, error) {
	if _, err := dst.Write([]byte(magicV2)); err != nil {
		return 0, err
	}
	fileID := make([]byte, 16)
	if _, err := rand.Read(fileID); err != nil {
		return 0, err
	}
	if _, err := dst.Write(fileID); err != nil {
		return 0, err
	}
	buf := make([]byte, chunkSize)
	var total int64
	var index uint64
	for {
		n, readErr := io.ReadFull(src, buf)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return total, readErr
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return total, err
		}
		sealed := aead.Seal(nil, nonce, buf[:n], streamAAD(rel, fileID, index, 0, false))
		if err := binary.Write(dst, binary.BigEndian, uint32(len(sealed))); err != nil {
			return total, err
		}
		if _, err := dst.Write(nonce); err != nil {
			return total, err
		}
		if _, err := dst.Write(sealed); err != nil {
			return total, err
		}
		total += int64(n)
		index++
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	// An authenticated terminal record makes truncation detectable and binds
	// the exact number and total plaintext length of all preceding chunks.
	if err := binary.Write(dst, binary.BigEndian, uint32(0)); err != nil {
		return total, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return total, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return total, err
	}
	if err := binary.Write(dst, binary.BigEndian, uint64(total)); err != nil {
		return total, err
	}
	if err := binary.Write(dst, binary.BigEndian, index); err != nil {
		return total, err
	}
	tag := aead.Seal(nil, nonce, nil, streamAAD(rel, fileID, index, uint64(total), true))
	if _, err := dst.Write(tag); err != nil {
		return total, err
	}
	return total, nil
}

func decryptStream(dst io.Writer, src io.Reader) error {
	return decryptStreamForPath(dst, src, "")
}

func decryptStreamForPath(dst io.Writer, src io.Reader, rel string) error {
	header := make([]byte, len(magic))
	if _, err := io.ReadFull(src, header); err != nil {
		return errors.New("invalid encrypted file")
	}
	if string(header) == magic {
		return decryptLegacyStream(dst, src)
	}
	if string(header) != magicV2 {
		return errors.New("invalid encrypted file")
	}
	fileID := make([]byte, 16)
	if _, err := io.ReadFull(src, fileID); err != nil {
		return errors.New("invalid encrypted file identity")
	}
	var index, total uint64
	for {
		var size uint32
		if err := binary.Read(src, binary.BigEndian, &size); err != nil {
			return err
		}
		if size == 0 {
			nonce := make([]byte, aead.NonceSize())
			if _, err := io.ReadFull(src, nonce); err != nil {
				return err
			}
			var expectedTotal, expectedChunks uint64
			if err := binary.Read(src, binary.BigEndian, &expectedTotal); err != nil {
				return err
			}
			if err := binary.Read(src, binary.BigEndian, &expectedChunks); err != nil {
				return err
			}
			tag := make([]byte, aead.Overhead())
			if _, err := io.ReadFull(src, tag); err != nil {
				return err
			}
			if expectedTotal != total || expectedChunks != index {
				return errors.New("encrypted file manifest mismatch")
			}
			if _, err := aead.Open(nil, nonce, tag, streamAAD(rel, fileID, index, total, true)); err != nil {
				return errors.New("encrypted file manifest authentication failed")
			}
			var trailing [1]byte
			if n, _ := src.Read(trailing[:]); n != 0 {
				return errors.New("unexpected encrypted file trailer")
			}
			return nil
		}
		if size > chunkSize+uint32(aead.Overhead()) {
			return errors.New("invalid chunk")
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(src, nonce); err != nil {
			return err
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(src, sealed); err != nil {
			return err
		}
		plain, err := aead.Open(nil, nonce, sealed, streamAAD(rel, fileID, index, 0, false))
		if err != nil {
			return err
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
		total += uint64(len(plain))
		index++
	}
}

func decryptLegacyStream(dst io.Writer, src io.Reader) error {
	for {
		var size uint32
		if err := binary.Read(src, binary.BigEndian, &size); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if size > chunkSize+uint32(aead.Overhead()) {
			return errors.New("invalid chunk")
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(src, nonce); err != nil {
			return err
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(src, sealed); err != nil {
			return err
		}
		plain, err := aead.Open(nil, nonce, sealed, nil)
		if err != nil {
			return err
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
	}
}

func writeFile(rel string, src io.Reader, mtime, maxBytes int64) error {
	return writeFileVerified(rel, src, mtime, maxBytes, "")
}

func writeFileVerified(rel string, src io.Reader, mtime, maxBytes int64, expectedSHA256 string) error {
	data, meta, err := pathsFor(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(data), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(data), ".warden-home-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if maxBytes <= 0 || maxBytes > 5*1024*1024*1024 {
		maxBytes = 5 * 1024 * 1024 * 1024
	}
	digest := sha256.New()
	size, err := encryptStreamForPath(tmp, io.TeeReader(io.LimitReader(src, maxBytes+1), digest), rel)
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if size > maxBytes {
		return errFileTooLarge
	}
	contentHash := hex.EncodeToString(digest.Sum(nil))
	if expectedSHA256 != "" && !strings.EqualFold(expectedSHA256, contentHash) {
		return errors.New("replicated content hash mismatch")
	}
	if err := os.Rename(name, data); err != nil {
		// Windows cannot atomically replace an existing destination. The
		// encrypted temporary file is already complete and authenticated.
		if removeErr := os.Remove(data); removeErr != nil && !os.IsNotExist(removeErr) {
			return err
		}
		if err := os.Rename(name, data); err != nil {
			return err
		}
	}
	if mtime == 0 {
		mtime = time.Now().Unix()
	}
	m := metadata{Size: size, ModTime: mtime, SHA256: contentHash, Valid: true, Exists: true}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	tag := aead.Seal(nil, nonce, nil, metadataHashAAD(rel, m))
	m.Auth = base64.RawURLEncoding.EncodeToString(append(nonce, tag...))
	raw, _ := json.Marshal(m)
	return atomicWrite(meta, raw, 0600)
}

func metadataAAD(rel string, size, mtime int64) []byte {
	return []byte(fmt.Sprintf("warden-home:metadata:v2:%s:%d:%d", filepath.ToSlash(rel), size, mtime))
}

// Bind the plaintext digest into authenticated metadata. Old v2 files remain
// readable; their digest is calculated from authenticated plaintext on listing.
func metadataHashAAD(rel string, m metadata) []byte {
	if m.SHA256 == "" {
		return metadataAAD(rel, m.Size, m.ModTime)
	}
	return []byte(fmt.Sprintf("warden-home:metadata:v3:%s:%d:%d:%s", filepath.ToSlash(rel), m.Size, m.ModTime, m.SHA256))
}

func prefixUsage(prefix string) int64 {
	data, _, err := pathsFor(prefix)
	if err != nil {
		return 0
	}
	root := strings.TrimSuffix(data, ".whome")
	var used int64
	walkResult := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && info != nil && !info.IsDir() && strings.HasSuffix(path, ".whome.meta") {
			m := loadMeta(path)
			if !m.Valid {
				return errors.New("invalid authenticated metadata")
			}
			if used > math.MaxInt64-m.Size {
				return errors.New("storage usage overflow")
			}
			used += m.Size
		}
		return nil
	})
	if walkResult != nil {
		return math.MaxInt64
	}
	historyBytes, err := historyUsageAndCleanup(prefix, false)
	if err != nil || used > math.MaxInt64-historyBytes {
		return math.MaxInt64
	}
	used += historyBytes
	return used
}

func storeAuthorizedFile(rel string, src io.Reader, mtime int64, g grant) (int, error) {
	return storeAuthorizedFileVerified(rel, src, mtime, g, "")
}

func storeAuthorizedFileVerified(rel string, src io.Reader, mtime int64, g grant, expectedSHA256 string, readdVersion ...string) (int, error) {
	deletion, err := readHomeDeletion(rel)
	if err != nil {
		return http.StatusInternalServerError, err
	} else if deletion != nil {
		if len(readdVersion) == 0 || readdVersion[0] != homeDeletionVersion(deletion) {
			return http.StatusConflict, errors.New("file was intentionally deleted; stale upload refused")
		}
		if err := purgeHomeDeletion(rel); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	maxBytes := g.MaxFileBytes
	if _, err := historyUsageAndCleanup(g.Prefix, true); err != nil {
		return 500, err
	}
	if maxBytes <= 0 || maxBytes > 5*1024*1024*1024 {
		maxBytes = 5 * 1024 * 1024 * 1024
	}
	allowed := maxBytes
	quotaLimited := false
	if g.QuotaBytes > 0 {
		_, metaPath, err := pathsFor(rel)
		if err != nil {
			return http.StatusBadRequest, err
		}
		existing := loadMeta(metaPath)
		if existing.Exists && !existing.Valid {
			return http.StatusInternalServerError, errors.New("stored file metadata authentication failed")
		}
		usage := prefixUsage(g.Prefix)
		if usage == math.MaxInt64 {
			return http.StatusInternalServerError, errors.New("storage usage cannot be authenticated")
		}
		remaining := g.QuotaBytes - usage + existing.Size
		growth, err := historyGrowth(rel, g.HistoryDays)
		if err != nil {
			return 500, err
		}
		remaining -= growth
		if remaining < allowed {
			allowed, quotaLimited = remaining, true
		}
		if allowed < 0 {
			allowed = 0
		}
		if allowed == 0 {
			return http.StatusInsufficientStorage, errFileTooLarge
		}
	}
	if err := archiveHomeVersion(rel, g.HistoryDays, false); err != nil {
		return 500, err
	}
	if err := writeFileVerified(rel, src, mtime, allowed, expectedSHA256); err != nil {
		if errors.Is(err, errFileTooLarge) {
			if quotaLimited {
				return http.StatusInsufficientStorage, err
			}
			return http.StatusRequestEntityTooLarge, err
		}
		return http.StatusInternalServerError, err
	}
	if deletion != nil {
		data, _, err := pathsFor(rel)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		if err := os.Remove(data + ".deleted"); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	return http.StatusNoContent, nil
}

func loadMeta(path string) metadata {
	raw, err := os.ReadFile(path)
	if err != nil {
		return metadata{Valid: os.IsNotExist(err), Exists: false}
	}
	var m metadata
	m.Exists = true
	if json.Unmarshal(raw, &m) != nil || m.Size < 0 {
		return m
	}
	dataPath := strings.TrimSuffix(path, ".meta")
	data, err := os.Open(dataPath)
	if err != nil {
		return m
	}
	header := make([]byte, len(magic))
	_, headerErr := io.ReadFull(data, header)
	data.Close()
	if headerErr != nil {
		return m
	}
	if m.Auth == "" {
		m.Valid = string(header) == magic && m.SHA256 == ""
		return m
	}
	rel, err := filepath.Rel(cfg.Root, strings.TrimSuffix(dataPath, ".whome"))
	if err != nil {
		return m
	}
	auth, err := base64.RawURLEncoding.DecodeString(m.Auth)
	if err != nil || len(auth) != aead.NonceSize()+aead.Overhead() {
		return m
	}
	nonce, tag := auth[:aead.NonceSize()], auth[aead.NonceSize():]
	_, err = aead.Open(nil, nonce, tag, metadataHashAAD(filepath.ToSlash(rel), m))
	m.Valid = err == nil && string(header) == magicV2
	return m
}

func listStoredFiles(prefix string) ([]fileEntry, error) {
	return listStoredEntries(prefix, false)
}

func listStoredEntries(prefix string, includeDirectories bool) ([]fileEntry, error) {
	root, _, err := pathsFor(prefix)
	if err != nil {
		return nil, err
	}
	root = strings.TrimSuffix(root, ".whome")
	var entries []fileEntry
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if info == nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink storage paths are not permitted")
		}
		if info.IsDir() {
			if strings.HasSuffix(path, ".whome.history") && isHomeHistoryDirectory(path) {
				return filepath.SkipDir
			}
			if includeDirectories && path != root {
				rel, err := filepath.Rel(cfg.Root, path)
				if err != nil {
					return err
				}
				entries = append(entries, fileEntry{Path: filepath.ToSlash(rel), IsDir: true})
			}
			return nil
		}
		if !strings.HasSuffix(path, ".whome") {
			return nil
		}
		rel, err := filepath.Rel(cfg.Root, strings.TrimSuffix(path, ".whome"))
		if err != nil {
			return nil
		}
		if deletion, err := readHomeDeletion(filepath.ToSlash(rel)); err != nil {
			return err
		} else if deletion != nil {
			return nil
		}
		m := loadMeta(path + ".meta")
		if !m.Valid {
			return errors.New("stored file metadata authentication failed")
		}
		digest := m.SHA256
		if digest == "" {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			err = decryptStreamForPath(h, f, filepath.ToSlash(rel))
			f.Close()
			if err != nil {
				return err
			}
			digest = hex.EncodeToString(h.Sum(nil))
		}
		entries = append(entries, fileEntry{Path: filepath.ToSlash(rel), Size: m.Size, ModTime: m.ModTime, SHA256: digest})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("path")
	g, err := verifyGrant(r, bearer(r), prefix, "read")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Complete already-confirmed deletions from older releases before reporting
	// sync success. This does not infer deletions from missing endpoint files.
	storageMu.Lock()
	release, err := acquireSpaceLock(g.Prefix)
	if err == nil {
		err = cleanupHomeDeletions(prefix)
		if err == nil {
			_, err = historyUsageAndCleanup(prefix, true)
		}
		release()
	}
	storageMu.Unlock()
	if err != nil {
		http.Error(w, "deletion cleanup failed; retry sync", http.StatusServiceUnavailable)
		return
	}
	entries, err := listStoredEntries(prefix, r.URL.Query().Get("include_directories") == "1")
	if err == nil && r.URL.Query().Get("include_deletions") == "1" {
		entries, err = appendHomeDeletions(prefix, entries)
	}
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Warden-Deletion-Tracking", "1")
	w.Header().Set("X-Warden-Conditional-Writes", "1")
	_ = json.NewEncoder(w).Encode(entries)
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	permission := map[string]string{http.MethodGet: "read", http.MethodPut: "write", http.MethodDelete: "delete"}[r.Method]
	if permission == "" {
		http.Error(w, "method", 405)
		return
	}
	g, err := verifyGrant(r, bearer(r), rel, permission)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	data, meta, err := pathsFor(rel)
	if err != nil {
		http.Error(w, "bad path", 400)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if deletion, err := readHomeDeletion(rel); err != nil {
			http.Error(w, "invalid deletion record", 500)
			return
		} else if deletion != nil {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(data)
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "read failed", 500)
			return
		}
		defer f.Close()
		m := loadMeta(meta)
		if !m.Valid {
			http.Error(w, "stored file metadata authentication failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Warden-Mtime", fmt.Sprint(m.ModTime))
		if m.SHA256 != "" {
			w.Header().Set("X-Warden-SHA256", m.SHA256)
		}
		w.Header().Set("Content-Length", fmt.Sprint(m.Size))
		if err := decryptStreamForPath(w, f, rel); err != nil {
			log.Printf("decrypt %s: %v", rel, err)
		}
	case http.MethodPut:
		if g.MaxFileBytes > 0 && r.ContentLength > g.MaxFileBytes {
			http.Error(w, "file exceeds this space's per-file limit", http.StatusRequestEntityTooLarge)
			return
		}
		mtime, _ := time.Parse(time.RFC3339, r.Header.Get("X-Warden-Mtime"))
		storageMu.Lock()
		release, lockErr := acquireSpaceLock(g.Prefix)
		if lockErr != nil {
			storageMu.Unlock()
			http.Error(w, "shared storage is busy", http.StatusServiceUnavailable)
			return
		}
		current, currentErr := storedVersion(rel)
		if currentErr != nil || (r.Header.Get("If-Match") != "" && strings.Trim(r.Header.Get("If-Match"), "\"") != current) || (r.Header.Get("If-None-Match") == "*" && current != "") {
			release()
			storageMu.Unlock()
			http.Error(w, "file changed since sync; retry safely", 412)
			return
		}
		status, writeErr := storeAuthorizedFileVerified(rel, r.Body, mtime.Unix(), g, "", r.Header.Get("X-Warden-Readd-Version"))
		if writeErr == nil {
			w.Header().Set("X-Warden-SHA256", loadMeta(meta).SHA256)
		}
		release()
		storageMu.Unlock()
		if writeErr != nil {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.WriteHeader(204)
	case http.MethodDelete:
		storageMu.Lock()
		release, lockErr := acquireSpaceLock(g.Prefix)
		if lockErr != nil {
			storageMu.Unlock()
			http.Error(w, "shared storage is busy", http.StatusServiceUnavailable)
			return
		}
		status, deleteErr := confirmHomeDeletion(rel, strings.Trim(r.Header.Get("If-Match"), "\""), g)
		if deleteErr == nil {
			if deletion, err := readHomeDeletion(rel); err == nil && deletion != nil {
				w.Header().Set("X-Warden-Deletion-Version", homeDeletionVersion(deletion))
			}
		}
		release()
		storageMu.Unlock()
		if deleteErr != nil {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.WriteHeader(status)
	}
}

func diskUsage() (int64, int64) {
	var used int64
	_ = filepath.Walk(cfg.Root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			used += info.Size()
		}
		return nil
	})
	return 0, used
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".warden-home-identity-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err == nil {
		return nil
	}
	// Windows cannot replace an existing file with os.Rename. The previous
	// certificate remains loaded by the running server until the complete new
	// pair has been validated and written.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(name, path)
}

func replicationStatePath() string {
	return filepath.Join(cfg.Root, ".warden-replication-state.json")
}

func loadReplicationState() error {
	state := map[string]int64{}
	raw, err := os.ReadFile(replicationStatePath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &state); err != nil {
			return fmt.Errorf("invalid replication state: %w", err)
		}
	}
	now := time.Now().Unix()
	for spaceID, syncedAt := range state {
		if strings.TrimSpace(spaceID) == "" || syncedAt <= 0 || syncedAt > now+300 {
			delete(state, spaceID)
		}
	}
	replicationMu.Lock()
	replicationOK = state
	replicationMu.Unlock()
	return nil
}

func recordReplicationSuccess(spaceID string) (bool, error) {
	replicationMu.Lock()
	defer replicationMu.Unlock()
	next := make(map[string]int64, len(replicationOK)+1)
	for id, syncedAt := range replicationOK {
		next[id] = syncedAt
	}
	first := next[spaceID] == 0
	next[spaceID] = time.Now().Unix()
	raw, err := json.Marshal(next)
	if err != nil {
		return false, err
	}
	if err := atomicWrite(replicationStatePath(), append(raw, '\n'), 0600); err != nil {
		return false, err
	}
	replicationOK = next
	return first, nil
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

func replicateFrom(p peer) {
	replicationKey := p.SpaceID + ":" + p.TargetNodeID
	if _, loaded := replicationActive.LoadOrStore(replicationKey, true); loaded {
		return
	}
	defer replicationActive.Delete(replicationKey)
	base := p.P2PURL
	if p.ConnectionMode != "p2p" {
		base = p.LocalURL
		if base == "" {
			base = p.PublicURL
		}
	}
	if base == "" {
		return
	}
	client, err := tlsClientForPeer(p)
	if err != nil {
		return
	}
	listURL := strings.TrimRight(base, "/") + "/v1/list?include_directories=1&include_deletions=1&path=" + url.QueryEscape(p.Prefix)
	req, _ := http.NewRequest(http.MethodGet, listURL, nil)
	req.Header.Set("Authorization", "Bearer "+p.Grant)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var entries []fileEntry
	if json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&entries) != nil {
		return
	}
	remotePaths := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		remotePaths[entry.Path] = struct{}{}
	}
	allOK := true
	for _, entry := range entries {
		if entry.Path != p.Prefix && !strings.HasPrefix(entry.Path, strings.TrimRight(p.Prefix, "/")+"/") {
			allOK = false
			continue
		}
		if entry.Deleted {
			storageMu.Lock()
			release, err := acquireSpaceLock(p.Prefix)
			if err != nil {
				allOK = false
			} else {
				if err := archiveHomeVersion(entry.Path, p.HistoryDays, true); err != nil {
					allOK = false
				} else if err := writeHomeDeletion(entry.Path, homeDeletion{SHA256: entry.SHA256, Size: entry.Size, DeletedAt: entry.ModTime}); err != nil {
					allOK = false
				}
				release()
			}
			storageMu.Unlock()
			continue
		}
		if entry.IsDir {
			if entry.Path != p.Prefix && !strings.HasPrefix(entry.Path, strings.TrimRight(p.Prefix, "/")+"/") {
				allOK = false
				continue
			}
			storageMu.Lock()
			release, err := acquireSpaceLock(p.Prefix)
			if err != nil {
				allOK = false
			} else {
				if err := createStoredDirectory(entry.Path); err != nil {
					allOK = false
				}
				release()
			}
			storageMu.Unlock()
			continue
		}
		_, metaPath, err := pathsFor(entry.Path)
		if err != nil {
			continue
		}
		deletion, deletionErr := readHomeDeletion(entry.Path)
		if deletionErr != nil {
			allOK = false
			continue
		}
		if local := loadMeta(metaPath); deletion == nil && local.Exists && local.Valid && local.Size == entry.Size && entry.SHA256 != "" && local.SHA256 == entry.SHA256 {
			continue
		}
		u := strings.TrimRight(base, "/") + "/v1/file?path=" + url.QueryEscape(entry.Path)
		get, _ := http.NewRequest(http.MethodGet, u, nil)
		get.Header.Set("Authorization", "Bearer "+p.Grant)
		fileResp, err := client.Do(get)
		if err != nil {
			allOK = false
			continue
		}
		if fileResp.StatusCode == 200 {
			storageMu.Lock()
			release, lockErr := acquireSpaceLock(p.Prefix)
			if lockErr == nil {
				// The authoritative primary now lists an active file at this path.
				// Replace a replica's old tombstone only after verified download.
				readdVersion := ""
				if deletion, err := readHomeDeletion(entry.Path); err == nil && deletion != nil {
					readdVersion = homeDeletionVersion(deletion)
				}
				_, writeErr := storeAuthorizedFileVerified(entry.Path, fileResp.Body, entry.ModTime, grant{
					Prefix: p.Prefix, MaxFileBytes: p.MaxFileBytes, QuotaBytes: p.QuotaBytes, HistoryDays: p.HistoryDays,
				}, entry.SHA256, readdVersion)
				if writeErr != nil {
					allOK = false
				}
				release()
			} else {
				allOK = false
			}
			storageMu.Unlock()
		} else {
			allOK = false
		}
		fileResp.Body.Close()
	}
	// A replica is an exact mirror, including deletions. Apply removals only
	// after a complete, successful remote listing and download pass so a
	// transient or truncated response can never erase backup data.
	if allOK {
		storageMu.Lock()
		release, lockErr := acquireSpaceLock(p.Prefix)
		if lockErr != nil {
			allOK = false
		} else {
			localEntries, listErr := listStoredFiles(p.Prefix)
			if listErr != nil {
				allOK = false
			} else {
				for _, local := range localEntries {
					if _, exists := remotePaths[local.Path]; exists {
						continue
					}
					dataPath, metaPath, pathErr := pathsFor(local.Path)
					if pathErr != nil {
						allOK = false
						continue
					}
					if err := os.Remove(dataPath); err != nil && !os.IsNotExist(err) {
						allOK = false
					}
					if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
						allOK = false
					}
				}
			}
			release()
		}
		storageMu.Unlock()
	}
	if allOK {
		firstSuccessfulSync, stateErr := recordReplicationSuccess(p.SpaceID)
		if stateErr != nil {
			log.Printf("Persist replication readiness for %s: %v", p.SpaceID, stateErr)
		} else if firstSuccessfulSync {
			select {
			case replicationReady <- struct{}{}:
			default:
			}
		}
	}
}

func heartbeatLoop(stop <-chan struct{}) {
	client := &http.Client{Timeout: 30 * time.Second}
	for {
		if err := ensureNodeCertificate(configPathInUse, 48*time.Hour); err != nil {
			log.Printf("Warden Home certificate renewal deferred: %v", err)
		}
		capacity, used := diskUsage()
		replicationMu.Lock()
		replicationState := make(map[string]int64, len(replicationOK))
		for spaceID, syncedAt := range replicationOK {
			replicationState[spaceID] = syncedAt
		}
		replicationMu.Unlock()
		body, _ := json.Marshal(map[string]interface{}{"capacity_bytes": capacity, "used_bytes": used, "capabilities": map[string]interface{}{"os": runtime.GOOS, "arch": runtime.GOARCH, "version": homeNodeVersion, "managed_updates": true, "encrypted_at_rest": true, "encrypted_history": true, "encryption_key_id": encryptionKeyID, "replication": cfg.Replication, "p2p": true, "p2p_transport": "webrtc-direct", "replication_sync": replicationState, "storage_cluster_id": cfg.StorageClusterID, "independent_backup": backupStatus(), "package_cache": cfg.PackageCacheMaxBytes > 0}})
		req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.WardenURL, "/")+"/api/home-node/heartbeat", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Warden-Home-Key", cfg.NodeKey)
		if resp, err := client.Do(req); err == nil {
			var result heartbeatResponse
			_ = json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&result)
			resp.Body.Close()
			if cfg.Replication {
				for _, p := range result.ReplicationPeers {
					go replicateFrom(p)
				}
			}
			considerManagedUpdate(result.Update)
		}
		select {
		case <-stop:
			return
		case <-replicationReady:
		case <-time.After(5 * time.Minute):
		}
	}
}

func loadConfig(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	configPathInUse = path
	if cfg.NodeID != "" && cfg.NodeKey != "" && cfg.WardenURL != "" {
		if err := ensureNodeCertificate(path, 0); err != nil {
			return fmt.Errorf("bootstrap Warden Home certificate: %w", err)
		}
	}
	if cfg.NodeID == "" || cfg.NodeKey == "" || cfg.WardenURL == "" || cfg.ServerPublicKey == "" || cfg.Root == "" || cfg.TLSCert == "" || cfg.TLSKey == "" || cfg.EncryptionKey == "" {
		return errors.New("missing required config")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":9443"
	}
	rawPub, err := decodeB64(cfg.ServerPublicKey)
	if err != nil || len(rawPub) != ed25519.PublicKeySize {
		return errors.New("invalid server public key")
	}
	pub = ed25519.PublicKey(rawPub)
	key, err := decodeB64(cfg.EncryptionKey)
	if err != nil || len(key) != 32 {
		return errors.New("encryption_key must be base64 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}
	keyDigest := sha256.Sum256(key)
	encryptionKeyID = hex.EncodeToString(keyDigest[:])
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		peerClientCert, err = tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return err
		}
		peerCertLoaded = true
	}
	if cfg.PublicMode && (cfg.ClientCA == "" || !peerCertLoaded) {
		return errors.New("public_mode requires client_ca and client certificate")
	}
	if err := os.MkdirAll(cfg.Root, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(cfg.Root, ".warden-restore-incomplete")); err == nil {
		return errors.New("refusing incomplete restored Home store")
	} else if !os.IsNotExist(err) {
		return err
	}
	return loadReplicationState()
}

func runConfiguredServer(path string, stop <-chan struct{}) error {
	if err := loadConfig(path); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("/v1/list", handleList)
	mux.HandleFunc("/v1/directory", handleDirectory)
	mux.HandleFunc("/v1/file", handleFile)
	mux.HandleFunc("/v1/history", handleHistory)
	mux.HandleFunc("/v1/package", handlePackageCache)
	servingCertificate, err := watchServingCertificate(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate := servingCertificate.Load()
			if certificate == nil {
				return nil, errors.New("TLS certificate is unavailable")
			}
			return certificate, nil
		},
	}
	if cfg.ClientCA != "" {
		raw, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return errors.New("invalid client CA")
		}
		tlsCfg.ClientCAs = pool
		// Permit unauthenticated transport only to the minimal /health endpoint.
		// Data handlers independently require a verified certificate whose
		// Warden identity matches the signed grant.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	server := &http.Server{Addr: cfg.Listen, Handler: http.MaxBytesHandler(mux, 5*1024*1024*1024+1024), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, WriteTimeout: 10 * time.Minute}
	go heartbeatLoop(stop)
	go backupLoop(stop)
	go homeP2PLoop(stop)
	log.Printf("Warden Home Node %s listening on %s", cfg.NodeID, cfg.Listen)
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func main() {
	if handled, err := runAsSystemService(); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	command, args := "serve", os.Args[1:]
	if len(args) > 0 && (args[0] == "serve" || args[0] == "install" || args[0] == "upgrade" || args[0] == "uninstall" || args[0] == "apply-update" || args[0] == "backup" || args[0] == "verify-backup" || args[0] == "restore-backup") {
		command, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	path := flags.String("config", "warden-home.json", "configuration file")
	manifest := flags.String("manifest", "", "signed managed-update manifest")
	snapshot := flags.String("snapshot", "", "independent snapshot ID")
	restoreRoot := flags.String("restore-root", "", "new, non-existing recovery directory")
	_ = flags.Parse(args)
	switch command {
	case "backup", "verify-backup", "restore-backup":
		if err := loadBackupConfig(*path); err != nil {
			log.Fatal(err)
		}
		var result backupSummary
		var err error
		switch command {
		case "backup":
			result, err = createBackup()
		case "verify-backup":
			result, err = verifyBackup(*snapshot)
		case "restore-backup":
			result, err = restoreBackup(*snapshot, *restoreRoot)
		}
		if err != nil {
			log.Fatal(err)
		}
		encoded, _ := json.Marshal(result)
		fmt.Println(string(encoded))
	case "install":
		if err := installSystemService(*path); err != nil {
			log.Fatal(err)
		}
		log.Print("Warden Home service installed and started")
	case "uninstall":
		if err := uninstallSystemService(); err != nil {
			log.Fatal(err)
		}
		log.Print("Warden Home service removed; configuration, keys, and encrypted data were preserved")
	case "upgrade":
		if err := upgradeSystemService(); err != nil {
			log.Fatal(err)
		}
		log.Print("Warden Home service upgraded and restarted; configuration, keys, and encrypted data were preserved")
	case "apply-update":
		if *manifest == "" {
			log.Fatal("managed update manifest is required")
		}
		if err := loadConfig(*path); err != nil {
			log.Fatal(err)
		}
		if err := applyManagedUpdateManifest(*manifest); err != nil {
			log.Fatal(err)
		}
		log.Print("Signed managed Warden Home update applied")
	default:
		stop := make(chan struct{})
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		go func() { <-signals; close(stop) }()
		if err := runConfiguredServer(*path, stop); err != nil {
			log.Fatal(err)
		}
	}
}
