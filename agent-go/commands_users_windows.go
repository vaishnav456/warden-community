package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf16"
)

// ── User management ───────────────────────────────────────────────────────────

func createUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	password, _ := p["password"].(string)
	fullName, _ := p["full_name"].(string)
	profilePhoto, _ := p["profile_photo"].(string)
	isAdmin, _ := p["is_admin"].(bool)
	mustChange, _ := p["must_change_password"].(bool)
	purpose, _ := p["purpose"].(string)
	if username == "" || password == "" {
		return 1, "", fmt.Errorf("username and password are required")
	}
	if err := createLocalUserSecure(username, password, fullName, mustChange); err != nil {
		// A recovery account deliberately survives uninstall/re-enrollment.
		// Reconcile only an explicitly marked recovery job; never take over an
		// arbitrary pre-existing local account from a normal CREATE_USER job.
		if purpose != "warden_recovery" || !errors.Is(err, syscall.Errno(2224)) {
			return 1, "", fmt.Errorf("create local user: %w", err)
		}
		if err := setLocalUserPasswordSecure(username, password); err != nil {
			return 1, "", fmt.Errorf("rotate recovery account password: %w", err)
		}
		if fullName != "" {
			if err := setLocalUserFullNameSecure(username, fullName); err != nil {
				return 1, "", fmt.Errorf("update recovery account name: %w", err)
			}
		}
	}
	if isAdmin {
		if groupErr := ensureLocalGroupMemberSecure("Administrators", username); groupErr != nil {
			// Administrator membership is part of the requested account state.
			// Do not report success with a silently under-privileged account.
			if purpose != "warden_recovery" {
				_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			}
			return 1, "", fmt.Errorf("grant administrator rights: %w", groupErr)
		}
	}
	if profilePhoto != "" {
		if err := applyUserProfilePicture(username, profilePhoto); err != nil {
			// A requested portrait is part of the desired account state. Avoid
			// reporting a half-provisioned user when Windows rejects the image.
			_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			return 1, "", fmt.Errorf("set profile photo: %w", err)
		}
	}
	return 0, fmt.Sprintf("Local account %s provisioned securely", username), nil
}

func decodeSECEditConfig(data []byte) string {
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		words := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			words = append(words, binary.LittleEndian.Uint16(data[i:i+2]))
		}
		return string(utf16.Decode(words))
	}
	return string(data)
}

func encodeSECEditConfig(text string) []byte {
	words := utf16.Encode([]rune(text))
	data := make([]byte, 2+len(words)*2)
	data[0], data[1] = 0xff, 0xfe
	for i, word := range words {
		binary.LittleEndian.PutUint16(data[2+i*2:], word)
	}
	return data
}

func addDeniedNetworkLogonSID(configText, sid string) (string, error) {
	if !regexp.MustCompile(`^S-1-(?:\d+-){1,14}\d+$`).MatchString(sid) {
		return "", fmt.Errorf("invalid Windows SID")
	}
	lines := strings.Split(strings.ReplaceAll(configText, "\r\n", "\n"), "\n")
	sectionIndex := -1
	insertIndex := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(trimmed, "[Privilege Rights]") {
			sectionIndex, insertIndex = i, i+1
			continue
		}
		if sectionIndex >= 0 && i > sectionIndex && strings.HasPrefix(trimmed, "[") {
			if insertIndex < 0 {
				insertIndex = i
			}
			break
		}
		if sectionIndex >= 0 && strings.HasPrefix(strings.ToLower(trimmed), "sedenynetworklogonright") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				return "", fmt.Errorf("malformed SeDenyNetworkLogonRight")
			}
			wanted := "*" + sid
			for _, existing := range strings.Split(parts[1], ",") {
				if strings.EqualFold(strings.TrimSpace(existing), wanted) {
					return strings.Join(lines, "\r\n"), nil
				}
			}
			value := strings.TrimSpace(parts[1])
			if value != "" {
				value += ","
			}
			lines[i] = "SeDenyNetworkLogonRight = " + value + wanted
			return strings.Join(lines, "\r\n"), nil
		}
		if sectionIndex >= 0 {
			insertIndex = i + 1
		}
	}
	if sectionIndex < 0 {
		return "", fmt.Errorf("secedit export omitted Privilege Rights")
	}
	line := "SeDenyNetworkLogonRight = *" + sid
	lines = append(lines[:insertIndex], append([]string{line}, lines[insertIndex:]...)...)
	return strings.Join(lines, "\r\n"), nil
}

func denyNetworkLogon(username string) error {
	sid, _, err := lookupWindowsAccountIdentity(username)
	if err != nil {
		return fmt.Errorf("resolve managed identity SID: %w", err)
	}
	dir, err := os.MkdirTemp("", "warden-user-rights-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "rights.inf")
	dbPath := filepath.Join(dir, "rights.sdb")
	if out, err := exec.Command("secedit", "/export", "/cfg", cfgPath, "/areas", "USER_RIGHTS", "/quiet").CombinedOutput(); err != nil {
		return fmt.Errorf("export user rights: %w: %s", err, string(out))
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	updated, err := addDeniedNetworkLogonSID(decodeSECEditConfig(raw), sid)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, encodeSECEditConfig(updated), 0600); err != nil {
		return err
	}
	if out, err := exec.Command("secedit", "/configure", "/db", dbPath, "/cfg", cfgPath,
		"/areas", "USER_RIGHTS", "/overwrite", "/quiet").CombinedOutput(); err != nil {
		return fmt.Errorf("apply user rights: %w: %s", err, string(out))
	}
	return nil
}

func managedIdentityProvisionAllowed(accountExists, secretExists, recoverExisting bool) bool {
	return !accountExists || secretExists || recoverExisting
}

func provisionWardenIdentity(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	credentialMode, _ := p["credential_mode"].(string)
	if credentialMode != "managed_shadow_v1" {
		// Backward compatibility for already-queued pre-provider jobs. New
		// servers never put the reusable Warden password in endpoint jobs.
		code, output, err := createUser(p)
		if err != nil {
			return code, output, err
		}
		if err := denyNetworkLogon(username); err != nil {
			_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			return 1, output, fmt.Errorf("secure Warden identity: %w", err)
		}
		return 0, fmt.Sprintf("Warden identity %s provisioned; network logon denied", username), nil
	}

	if !identityUsernamePattern.MatchString(username) {
		return 1, "", fmt.Errorf("invalid managed identity username")
	}
	fullName, _ := p["full_name"].(string)
	profilePhoto, _ := p["profile_photo"].(string)
	isAdmin, _ := p["is_admin"].(bool)
	recoverExisting, _ := p["recover_existing"].(bool)

	_, accountErr := exec.Command("net", "user", username).CombinedOutput()
	accountExists := accountErr == nil
	password, secretExists, err := managedIdentityPassword(username)
	if err != nil {
		return 1, "", err
	}
	if !managedIdentityProvisionAllowed(accountExists, secretExists, recoverExisting) {
		return 1, "", fmt.Errorf("refusing to take over an unmanaged local account")
	}
	createdSecret := false
	if !secretExists {
		password, err = newManagedIdentityPassword()
		if err != nil {
			return 1, "", fmt.Errorf("generate device credential: %w", err)
		}
		if err := putManagedIdentityPassword(username, password); err != nil {
			return 1, "", err
		}
		createdSecret = true
	}

	if !accountExists {
		if createErr := createLocalUserSecure(username, password, fullName, false); createErr != nil {
			if createdSecret {
				_ = removeManagedIdentityPassword(username)
			}
			return 1, "", fmt.Errorf("create managed shadow account: %w", createErr)
		}
		accountExists = true
	} else {
		if resetErr := setLocalUserPasswordSecure(username, password); resetErr != nil {
			return 1, "", fmt.Errorf("repair managed shadow credential: %w", resetErr)
		}
	}
	if out, enableErr := exec.Command("net", "user", username, "/active:yes").CombinedOutput(); enableErr != nil {
		return 1, string(out), fmt.Errorf("enable managed shadow account: %w", enableErr)
	}
	groupAction := "/delete"
	if isAdmin {
		groupAction = "/add"
	}
	// Removing a standard user that is not a member returns an error; only an
	// add failure is fatal because it would violate assigned privilege state.
	if out, groupErr := exec.Command("net", "localgroup", "Administrators", username, groupAction).CombinedOutput(); groupErr != nil && isAdmin {
		return 1, string(out), fmt.Errorf("grant managed administrator rights: %w", groupErr)
	}
	if profilePhoto != "" {
		if err := applyUserProfilePicture(username, profilePhoto); err != nil {
			return 1, "", fmt.Errorf("set managed identity profile photo: %w", err)
		}
	}
	if err := denyNetworkLogon(username); err != nil {
		if createdSecret {
			_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
			_ = removeManagedIdentityPassword(username)
		}
		return 1, "", fmt.Errorf("secure Warden identity: %w", err)
	}
	return 0, fmt.Sprintf("Warden identity %s provisioned with a machine-bound shadow credential", username), nil
}

func deleteUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	sid, _, sidErr := lookupWindowsAccountIdentity(username)
	out, err := exec.Command("net", "user", username, "/delete").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("net user delete: %w", err)
	}
	if sidErr == nil {
		if err := removeUserProfilePicture(sid); err != nil {
			return 1, string(out), fmt.Errorf("user deleted but profile-photo cleanup failed: %w", err)
		}
	}
	if err := removeManagedIdentityPassword(username); err != nil {
		return 1, string(out), fmt.Errorf("user deleted but managed credential cleanup failed: %w", err)
	}
	return 0, fmt.Sprintf("User %s deleted", username), nil
}

func resetPassword(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	newPw, _ := p["new_password"].(string)
	if username == "" || newPw == "" {
		return 1, "", fmt.Errorf("username and new_password required")
	}
	if _, managed, err := managedIdentityPassword(username); err != nil {
		return 1, "", fmt.Errorf("check managed identity ownership: %w", err)
	} else if managed {
		return 1, "", fmt.Errorf("managed Warden identity passwords must be changed from Central Directory")
	}
	if err := setLocalUserPasswordSecure(username, newPw); err != nil {
		return 1, "", fmt.Errorf("set local user password: %w", err)
	}
	return 0, fmt.Sprintf("Password reset for %s", username), nil
}

func disableUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	out, err := exec.Command("net", "user", username, "/active:no").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("disable user: %w", err)
	}
	return 0, fmt.Sprintf("User %s disabled", username), nil
}

func enableUser(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	out, err := exec.Command("net", "user", username, "/active:yes").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("enable user: %w", err)
	}
	return 0, fmt.Sprintf("User %s enabled", username), nil
}

// applyWardenOnlyLockdown converts an enrolled workstation to Warden-managed
// interactive access.  It deliberately runs only after the server has seen a
// successful PROVISION_WARDEN_IDENTITY result.  The approved identity and a
// separate recovery administrator are made usable before any existing account
// is disabled, preventing a partial failure from locking everybody out.
func applyWardenOnlyLockdown(p map[string]interface{}) (int, string, error) {
	recoveryUsername, _ := p["recovery_admin_username"].(string)
	recoveryPassword, _ := p["recovery_admin_password"].(string)
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`).MatchString(recoveryUsername) || recoveryPassword == "" {
		return 1, "", fmt.Errorf("valid recovery administrator credentials are required")
	}
	allowed := map[string]bool{strings.ToLower(recoveryUsername): true}
	if raw, ok := p["allowed_users"].([]interface{}); ok {
		for _, value := range raw {
			username, ok := value.(string)
			if ok && regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`).MatchString(username) {
				allowed[strings.ToLower(username)] = true
			}
		}
	}
	if len(allowed) < 2 {
		return 1, "", fmt.Errorf("at least one Warden identity is required before lockdown")
	}

	// Confirm every approved Warden user exists and is enabled first.
	for username := range allowed {
		if strings.EqualFold(username, recoveryUsername) {
			continue
		}
		if out, err := exec.Command("net", "user", username).CombinedOutput(); err != nil {
			return 1, string(out), fmt.Errorf("approved Warden identity %s is not usable", username)
		}
		if out, err := exec.Command("net", "user", username, "/active:yes").CombinedOutput(); err != nil {
			return 1, string(out), fmt.Errorf("enable approved Warden identity %s: %w", username, err)
		}
	}

	// Create or rotate the independently controlled break-glass administrator.
	if _, err := exec.Command("net", "user", recoveryUsername).CombinedOutput(); err != nil {
		if createErr := createLocalUserSecure(recoveryUsername, recoveryPassword, "Warden Recovery Administrator", false); createErr != nil {
			return 1, "", fmt.Errorf("create recovery administrator: %w", createErr)
		}
	} else if resetErr := setLocalUserPasswordSecure(recoveryUsername, recoveryPassword); resetErr != nil {
		return 1, "", fmt.Errorf("rotate recovery administrator password: %w", resetErr)
	}
	if out, err := exec.Command("net", "user", recoveryUsername, "/active:yes").CombinedOutput(); err != nil {
		return 1, string(out), fmt.Errorf("enable recovery administrator: %w", err)
	}
	if out, err := exec.Command("net", "localgroup", "Administrators", recoveryUsername, "/add").CombinedOutput(); err != nil && !strings.Contains(strings.ToLower(string(out)), "already a member") {
		return 1, string(out), fmt.Errorf("grant recovery administrator rights: %w", err)
	}

	type localUser struct {
		Name    string `json:"Name"`
		SID     string `json:"SID"`
		Enabled bool   `json:"Enabled"`
	}
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-LocalUser | Select-Object Name,@{N='SID';E={$_.SID.Value}},Enabled | ConvertTo-Json -Compress`).CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("enumerate local users: %w", err)
	}
	raw := bytes.TrimSpace(out)
	if len(raw) > 0 && raw[0] == '{' {
		raw = append(append([]byte{'['}, raw...), ']')
	}
	var users []localUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return 1, string(out), fmt.Errorf("decode local users: %w", err)
	}
	disabled := []string{}
	for _, user := range users {
		nameFolded := strings.ToLower(user.Name)
		// Guest, DefaultAccount, and WDAGUtilityAccount are Windows-managed
		// identities. They are normally disabled already and are never made
		// usable by this workflow.
		systemManaged := strings.HasSuffix(user.SID, "-501") || strings.HasSuffix(user.SID, "-503") || strings.HasSuffix(user.SID, "-504")
		if allowed[nameFolded] || systemManaged || !user.Enabled {
			continue
		}
		if disableOut, disableErr := exec.Command("net", "user", user.Name, "/active:no").CombinedOutput(); disableErr != nil {
			return 1, string(disableOut), fmt.Errorf("disable unmanaged local user %s: %w", user.Name, disableErr)
		}
		disabled = append(disabled, user.Name)
	}

	restartOut, restartErr := exec.Command("shutdown", "/r", "/t", "30", "/d", "p:4:1", "/c", "Warden-only enrollment completed").CombinedOutput()
	if restartErr != nil {
		return 1, string(restartOut), fmt.Errorf("schedule post-enrollment restart: %w", restartErr)
	}
	return 0, fmt.Sprintf("Warden-only mode enabled; disabled %d unmanaged account(s): %s; restart scheduled in 30 seconds", len(disabled), strings.Join(disabled, ", ")), nil
}

// configureDeviceIdentity applies the zero-touch enrollment profile after the
// agent has authenticated. A DNS suffix is a Warden-managed machine identity
// and does not pretend to join an Active Directory domain.
func configureDeviceIdentity(p map[string]interface{}) (int, string, error) {
	targetHostname, _ := p["hostname"].(string)
	targetHostname = strings.ToUpper(strings.TrimSpace(targetHostname))
	domainSuffix, _ := p["domain_suffix"].(string)
	domainSuffix = strings.ToLower(strings.Trim(strings.TrimSpace(domainSuffix), "."))
	if targetHostname != "" && !regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{0,13}[A-Z0-9]$|^[A-Z0-9]$`).MatchString(targetHostname) {
		return 1, "", fmt.Errorf("managed hostname must be 1-15 letters, numbers or hyphens")
	}
	if domainSuffix != "" && (len(domainSuffix) > 253 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`).MatchString(domainSuffix)) {
		return 1, "", fmt.Errorf("invalid managed DNS suffix")
	}
	if targetHostname == "" && domainSuffix == "" {
		return 0, "No managed device identity requested", nil
	}

	currentHostname, _ := os.Hostname()
	hostnameChanged := targetHostname != "" && !strings.EqualFold(currentHostname, targetHostname)
	domainChanged := domainSuffix != "" && !strings.EqualFold(currentManagedDNSSuffix(), domainSuffix)
	if !hostnameChanged && !domainChanged {
		return 0, "Managed device identity already applied", nil
	}

	if hostnameChanged {
		script := fmt.Sprintf("Rename-Computer -NewName '%s' -Force -ErrorAction Stop", targetHostname)
		if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
			return 1, string(out), fmt.Errorf("rename computer: %w", err)
		}
	}
	if domainChanged {
		key, _, err := registry.CreateKey(
			registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
			registry.QUERY_VALUE|registry.SET_VALUE,
		)
		if err != nil {
			return 1, "", fmt.Errorf("open DNS identity registry: %w", err)
		}
		defer key.Close()
		if err := key.SetStringValue("NV Domain", domainSuffix); err != nil {
			return 1, "", fmt.Errorf("persist managed DNS suffix: %w", err)
		}
		if err := key.SetStringValue("Domain", domainSuffix); err != nil {
			return 1, "", fmt.Errorf("activate managed DNS suffix: %w", err)
		}
	}

	if !deviceIdentityRestartRequested(p) {
		return 0, fmt.Sprintf("Managed identity applied (hostname=%s, dns_suffix=%s); no restart scheduled. The hostname takes effect after the next restart.", targetHostname, domainSuffix), nil
	}
	if out, err := exec.Command("shutdown.exe", "/r", "/t", "30", "/d", "p:4:1", "/c", "Warden device identity configured").CombinedOutput(); err != nil {
		return 1, string(out), fmt.Errorf("schedule device identity restart: %w", err)
	}
	return 0, fmt.Sprintf("Managed identity applied (hostname=%s, dns_suffix=%s); restart scheduled", targetHostname, domainSuffix), nil
}

func deviceIdentityRestartRequested(p map[string]interface{}) bool {
	restart, _ := p["restart"].(bool)
	return restart
}

func currentManagedDNSSuffix() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	if value, _, err := key.GetStringValue("Domain"); err == nil && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	value, _, _ := key.GetStringValue("NV Domain")
	return strings.TrimSpace(value)
}
