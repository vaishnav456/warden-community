package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"warden-agent/internal/moduletrust"
)

const moduleDirectory = `C:\Program Files\WardenAgentModules`
const moduleStatePath = dataDir + `\helpdesk-module-state.json`

type installedModule struct {
	Sequence uint64 `json:"sequence"`
	SHA256   string `json:"sha256"`
}

var moduleManagerMu sync.Mutex

func moduleClock() time.Time { return time.Unix(trustedCommandUnix(), 0) }
func moduleRequestHeaders(r *http.Request) error {
	c := getConfig()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	timestamp := fmt.Sprint(trustedCommandUnix())
	nonceHex := hex.EncodeToString(nonce[:])
	message := fmt.Sprintf("warden-module-v1|%s|%s|%s|%s|%s", c.EndpointID, r.Method, r.URL.Path, timestamp, nonceHex)
	certificate, signature, err := signWithDeviceKey([]byte(message))
	if err != nil {
		return err
	}
	clientMu.Lock()
	key := apiKey
	clientMu.Unlock()
	r.Header.Set("X-Agent-Key", key)
	r.Header.Set("X-Warden-Module-Time", timestamp)
	r.Header.Set("X-Warden-Module-Nonce", nonceHex)
	r.Header.Set("X-Warden-Module-Certificate", base64.StdEncoding.EncodeToString([]byte(certificate)))
	r.Header.Set("X-Warden-Module-Signature", signature)
	return addDeviceRequestProof(r, nil)
}
func moduleInstalled() (installedModule, error) {
	var state installedModule
	raw, err := os.ReadFile(moduleStatePath)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if len(raw) > 1024 || json.Unmarshal(raw, &state) != nil || state.Sequence == 0 || len(state.SHA256) != 64 {
		return state, errors.New("module state invalid")
	}
	return state, nil
}
func fetchHelpdeskGrant(ctx context.Context, state installedModule) (*moduletrust.Approved, *http.Client, error) {
	c := getConfig()
	key, err := loadServerPubkey(c.ServerEd25519Pubkey)
	if err != nil {
		return nil, nil, err
	}
	clientMu.Lock()
	original := httpClient
	clientMu.Unlock()
	if original == nil {
		return nil, nil, errors.New("module transport unavailable")
	}
	client := *original
	client.Timeout = 10 * time.Second
	client.CheckRedirect = rejectRedirect
	req, err := http.NewRequestWithContext(ctx, "GET", c.ServerURL+"/api/agent/modules/helpdesk/manifest", nil)
	if err != nil {
		return nil, nil, err
	}
	if err = moduleRequestHeaders(req); err != nil {
		return nil, nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, nil, errors.New("module access unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, moduletrust.MaxManifestBytes+1))
	if err != nil {
		return nil, nil, err
	}
	approved, err := moduletrust.Verify(raw, moduletrust.Context{PublicKey: key, TenantID: c.CompanyID, EndpointID: c.EndpointID, ServerURL: c.ServerURL, CoreVersion: agentVersion, InstalledSequence: state.Sequence, InstalledSHA256: state.SHA256, Now: moduleClock()})
	return approved, &client, err
}

// Reject every existing ancestor's reparse point, not just the final file.
func moduleNoReparse(path string) error {
	for current := filepath.Clean(path); current != ""; current = filepath.Dir(current) {
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return err
		}
		if err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("module reparse point rejected")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
func moduleProtectDirectory(path string) error {
	if err := moduleNoReparse(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)")
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION, owner, nil, acl, nil)
}
func persistModule(state installedModule) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dataDir, ".module-state-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(name)
	to, _ := windows.UTF16PtrFromString(moduleStatePath)
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func syncHelpdeskModule(ctx context.Context) error {
	moduleManagerMu.Lock()
	defer moduleManagerMu.Unlock()
	state, err := moduleInstalled()
	if err != nil {
		return err
	}
	approved, client, err := fetchHelpdeskGrant(ctx, state)
	if err != nil {
		return err
	}
	grant := approved.Grant()
	directory := filepath.Join(moduleDirectory, "helpdesk")
	if err = moduleProtectDirectory(directory); err != nil {
		return err
	}
	target := filepath.Join(directory, grant.SHA256+".exe")
	if moduleNoReparse(target) == nil && verifyExecutionArtifact(target, grant.SHA256, requireAuthenticodeUpdates()) == nil {
		return persistModule(installedModule{grant.Sequence, grant.SHA256})
	}
	staging := filepath.Join(dataDir, "module-staging")
	if err = moduleNoReparse(staging); err != nil {
		return err
	}
	if err = os.MkdirAll(staging, 0700); err != nil {
		return err
	}
	pending, err := approved.StageWithClient(ctx, staging, moduleRequestHeaders, client, moduleClock)
	if err != nil {
		return err
	}
	defer os.Remove(pending)
	if err = verifyExecutionArtifact(pending, grant.SHA256, requireAuthenticodeUpdates()); err != nil {
		return err
	}
	// Same volume; rename is atomic. Hash-addressed old releases remain recoverable.
	if err = os.Rename(pending, target); err != nil {
		return err
	}
	// Rename preserves staging ACLs: explicitly make the verified blob readable
	// but never writable by ordinary users before returning a launch path.
	descriptor, err := windows.SecurityDescriptorFromString("O:SYD:P(A;;FA;;;SY)(A;;GRGX;;;BU)")
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	if err = verifyExecutionArtifact(target, grant.SHA256, requireAuthenticodeUpdates()); err != nil {
		return err
	}
	return persistModule(installedModule{grant.Sequence, grant.SHA256})
}
func runModuleManager(stop <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	for {
		if err := syncHelpdeskModule(ctx); err != nil {
			logWarn("Optional Helpdesk module unavailable")
		}
		timer := time.NewTimer(time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func helpdeskModuleLaunchResponse() supportResponse {
	// Launch never waits for a long download or holds a broker while staging.
	if !moduleManagerMu.TryLock() {
		return supportResponse{Message: "Helpdesk is downloading. Try again shortly."}
	}
	defer moduleManagerMu.Unlock()
	state, err := moduleInstalled()
	if err != nil || state.Sequence == 0 {
		return supportResponse{Message: "Helpdesk is not installed or enabled yet."}
	}
	approved, _, err := fetchHelpdeskGrant(context.Background(), state)
	if err != nil {
		return supportResponse{Message: "Helpdesk permission could not be confirmed. Check connectivity or contact IT."}
	}
	grant := approved.Grant()
	if grant.SHA256 != state.SHA256 {
		return supportResponse{Message: "A Helpdesk update is being prepared. Try again shortly."}
	}
	path := filepath.Join(moduleDirectory, "helpdesk", state.SHA256+".exe")
	if moduleNoReparse(path) != nil || verifyExecutionArtifact(path, state.SHA256, requireAuthenticodeUpdates()) != nil {
		return supportResponse{Message: "Helpdesk verification failed."}
	}
	return supportResponse{OK: true, ModulePath: path, ModuleSHA256: state.SHA256}
}
func launchHelpdeskModule(mode string) int {
	if mode != "create" && mode != "tickets" {
		return 2
	}
	response, err := exchangeSupportRequest(supportRequest{Action: "module-launch"})
	if err != nil || !response.OK {
		runWardenUserDialog("Warden Helpdesk", "Helpdesk unavailable", response.Message, "Contact your organization administrator.", "warning", false)
		return 1
	}
	expected := filepath.Join(moduleDirectory, "helpdesk", response.ModuleSHA256+".exe")
	if len(response.ModuleSHA256) != 64 || response.ModulePath != expected || moduleNoReparse(expected) != nil || verifyExecutionArtifact(expected, response.ModuleSHA256, false) != nil {
		return 3
	}
	if err = exec.Command(expected, mode).Run(); err != nil {
		return 1
	}
	return 0
}
