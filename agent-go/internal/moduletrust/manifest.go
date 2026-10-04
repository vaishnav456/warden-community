// Package moduletrust verifies optional-module grants. It deliberately cannot
// download, install, execute code, grant remote access or change subscriptions.
package moduletrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxManifestBytes = 16384
const MaxPackageBytes = 64 * 1024 * 1024

type Envelope struct {
	Payload   string `json:"payload_b64"`
	Signature string `json:"signature_b64"`
}

// Grant is signed over the EXACT decoded payload bytes, not a reserialized
// object. Downloading is independently gated by live server authorization.
type Grant struct {
	Schema         int      `json:"schema"`
	ModuleID       string   `json:"module_id"`
	TenantID       string   `json:"tenant_id"`
	EndpointID     string   `json:"endpoint_id"`
	ReleaseID      string   `json:"release_id"`
	Sequence       uint64   `json:"release_sequence"`
	Version        string   `json:"version"`
	MinCoreVersion string   `json:"min_core_version"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	DownloadURL    string   `json:"download_url"`
	SHA256         string   `json:"sha256"`
	SizeBytes      int64    `json:"size_bytes"`
	Entitled       bool     `json:"entitled"`
	AdminEnabled   bool     `json:"admin_enabled"`
	Capabilities   []string `json:"capabilities"`
}

type Context struct {
	PublicKey                                    ed25519.PublicKey
	TenantID, EndpointID, ServerURL, CoreVersion string
	// The caller must load these from durable SYSTEM-protected state, not a
	// module-supplied config. Equal sequences must match the installed hash.
	InstalledSequence uint64
	InstalledSHA256   string
	// The caller supplies its authenticated server-clock anchor when needed.
	Now time.Time
}

type Approved struct{ grant Grant }

func (a *Approved) Grant() Grant {
	g := a.grant
	g.Capabilities = append([]string(nil), g.Capabilities...)
	return g
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var version = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

func strictJSON(raw []byte, target interface{}) error {
	// encoding/json otherwise silently accepts duplicate object keys. Reject
	// ambiguity, including case variants matched by Go's field decoder.
	check := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSON(check, 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return errors.New("trailing manifest data")
	}
	return nil
}

func uniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("manifest nesting too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[strings.ToLower(name)] {
				return errors.New("duplicate manifest key")
			}
			seen[strings.ToLower(name)] = true
			if err := uniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid manifest delimiter")
	}
	_, err = decoder.Token()
	return err
}

func versionAtLeast(actual, minimum string) bool {
	if !version.MatchString(actual) || !version.MatchString(minimum) {
		return false
	}
	a, b := strings.Split(actual, "."), strings.Split(minimum, ".")
	for i := 0; i < 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x > y
		}
	}
	return true
}

func Verify(raw []byte, context Context) (*Approved, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes || len(context.PublicKey) != ed25519.PublicKeySize || context.Now.IsZero() {
		return nil, errors.New("invalid manifest or verification context")
	}
	var envelope Envelope
	if err := strictJSON(raw, &envelope); err != nil {
		return nil, errors.New("invalid manifest envelope")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > 8192 {
		return nil, errors.New("invalid manifest payload")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(context.PublicKey, payload, signature) {
		return nil, errors.New("invalid module signature")
	}
	var grant Grant
	if err := strictJSON(payload, &grant); err != nil {
		return nil, errors.New("invalid signed manifest")
	}
	// A closed catalog, not an arbitrary executable/plugin loader. Future
	// modules need explicit capability review before adding a catalog entry.
	if grant.Schema != 1 || grant.ModuleID != "helpdesk" || !grant.Entitled || !grant.AdminEnabled {
		return nil, errors.New("module is not allowed")
	}
	if !uuid.MatchString(grant.TenantID) || !uuid.MatchString(grant.EndpointID) || !uuid.MatchString(grant.ReleaseID) || grant.TenantID != context.TenantID || grant.EndpointID != context.EndpointID {
		return nil, errors.New("module belongs to another tenant or endpoint")
	}
	now := context.Now.Unix()
	if grant.IssuedAt > now+30 || grant.IssuedAt < now-300 || grant.ExpiresAt <= now || grant.ExpiresAt <= grant.IssuedAt || grant.ExpiresAt-grant.IssuedAt > 300 {
		return nil, errors.New("module grant expired or outside clock bounds")
	}
	if grant.Sequence == 0 || grant.Sequence < context.InstalledSequence || (grant.Sequence == context.InstalledSequence && grant.SHA256 != context.InstalledSHA256) {
		return nil, errors.New("module downgrade or release substitution")
	}
	if !version.MatchString(grant.Version) || !versionAtLeast(context.CoreVersion, grant.MinCoreVersion) {
		return nil, errors.New("module requires a compatible Core version")
	}
	if !hash.MatchString(grant.SHA256) || grant.SizeBytes <= 0 || grant.SizeBytes > MaxPackageBytes {
		return nil, errors.New("invalid module hash or size")
	}
	if len(grant.Capabilities) != 2 || grant.Capabilities[0] != "helpdesk.tickets.read" || grant.Capabilities[1] != "helpdesk.tickets.write" {
		return nil, errors.New("module capability escalation")
	}
	base, err := url.Parse(context.ServerURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("untrusted server origin")
	}
	path := "/api/agent/modules/helpdesk/package/" + grant.ReleaseID
	asset, err := url.Parse(grant.DownloadURL)
	if err != nil || asset.Scheme != "https" || asset.Host != base.Host || asset.User != nil || asset.Fragment != "" || asset.RawQuery != "" || asset.RawPath != "" || asset.Path != path {
		return nil, errors.New("untrusted module download URL")
	}
	return &Approved{grant: grant}, nil
}

// VerifyPackage verifies a single executable blob, not an archive. The caller
// must stage it in a unique SYSTEM-owned directory, reject redirects, enforce
// Authenticode where required, verify the installed file again, and atomically
// persist its release sequence before permitting a least-privilege launch.
func (a *Approved) VerifyPackage(source io.Reader) error {
	if a == nil || a.grant.Sequence == 0 {
		return errors.New("unverified module grant")
	}
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(source, a.grant.SizeBytes+1))
	if err != nil {
		return fmt.Errorf("reading module: %w", err)
	}
	if read != a.grant.SizeBytes || hex.EncodeToString(digest.Sum(nil)) != a.grant.SHA256 {
		return errors.New("module size or SHA-256 mismatch")
	}
	return nil
}
