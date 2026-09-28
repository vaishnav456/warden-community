package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func vmIntegrationPassword(t *testing.T) string {
	t.Helper()
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("generate integration-test password: %v", err)
	}
	return "Warden.Vm-" + hex.EncodeToString(random)
}

// Run on a disposable, elevated Windows VM with:
//
//	set WARDEN_VM_INTEGRATION=1 && warden-agent-tests.exe -test.run TestVMLocalUserLifecycle -test.v
func TestVMLocalUserLifecycle(t *testing.T) {
	if os.Getenv("WARDEN_VM_INTEGRATION") != "1" {
		t.Skip("set WARDEN_VM_INTEGRATION=1 on a disposable elevated Windows VM")
	}

	const username = "WardenVmTest"
	initialPassword := vmIntegrationPassword(t)
	updatedPassword := vmIntegrationPassword(t)
	cleanup := func() {
		_, _ = exec.Command("net", "localgroup", "Administrators", username, "/delete").CombinedOutput()
		_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
		_ = removeElevationExpiry(username)
	}
	cleanup()
	t.Cleanup(cleanup)

	if code, output, err := createUser(map[string]interface{}{
		"username": username, "password": initialPassword,
		"full_name": "Warden VM Integration", "is_admin": false,
		"must_change_password": false,
	}); err != nil || code != 0 {
		t.Fatalf("createUser failed (code %d): %v: %s", code, err, output)
	}
	if output, err := exec.Command("net", "user", username).CombinedOutput(); err != nil {
		t.Fatalf("created account is missing: %v: %s", err, output)
	}
	if code, output, err := disableUser(map[string]interface{}{"username": username}); err != nil || code != 0 {
		t.Fatalf("disableUser failed (code %d): %v: %s", code, err, output)
	}
	if code, output, err := enableUser(map[string]interface{}{"username": username}); err != nil || code != 0 {
		t.Fatalf("enableUser failed (code %d): %v: %s", code, err, output)
	}
	if code, output, err := resetPassword(map[string]interface{}{
		"username": username, "new_password": updatedPassword,
	}); err != nil || code != 0 {
		t.Fatalf("resetPassword failed (code %d): %v: %s", code, err, output)
	}
	if code, output, err := grantElevation(map[string]interface{}{
		"username": username, "duration_minutes": float64(5),
	}); err != nil || code != 0 {
		t.Fatalf("grantElevation failed (code %d): %v: %s", code, err, output)
	}
	admins, err := exec.Command("net", "localgroup", "Administrators").CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(admins)), strings.ToLower(username)) {
		t.Fatalf("elevated account not present in Administrators: %v: %s", err, admins)
	}
	if code, output, err := revokeElevation(map[string]interface{}{"username": username}); err != nil || code != 0 {
		t.Fatalf("revokeElevation failed (code %d): %v: %s", code, err, output)
	}
	if code, output, err := deleteUser(map[string]interface{}{"username": username}); err != nil || code != 0 {
		t.Fatalf("deleteUser failed (code %d): %v: %s", code, err, output)
	}
	if _, err := exec.Command("net", "user", username).CombinedOutput(); err == nil {
		t.Fatal("deleted test account still exists")
	}
}

func TestVMRecoveryAccountReconciliation(t *testing.T) {
	if os.Getenv("WARDEN_VM_INTEGRATION") != "1" {
		t.Skip("set WARDEN_VM_INTEGRATION=1 on a disposable elevated Windows VM")
	}
	const username = "WardenRecoveryTest"
	oldPassword := vmIntegrationPassword(t)
	newPassword := vmIntegrationPassword(t)
	newerPassword := vmIntegrationPassword(t)
	cleanup := func() {
		_, _ = exec.Command("net", "localgroup", "Administrators", username, "/delete").CombinedOutput()
		_, _ = exec.Command("net", "user", username, "/delete").CombinedOutput()
	}
	cleanup()
	t.Cleanup(cleanup)
	if err := createLocalUserSecure(username, oldPassword, "Old recovery", false); err != nil {
		t.Fatalf("seed recovery account: %v", err)
	}
	if code, output, err := createUser(map[string]interface{}{
		"username": username, "password": newPassword,
		"full_name": "Warden Recovery Integration", "is_admin": true,
		"must_change_password": false, "purpose": "warden_recovery",
	}); err != nil || code != 0 {
		t.Fatalf("reconcile recovery account failed (code %d): %v: %s", code, err, output)
	}
	if code, output, err := createUser(map[string]interface{}{
		"username": username, "password": newerPassword,
		"full_name": "Warden Recovery Integration", "is_admin": true,
		"must_change_password": false, "purpose": "warden_recovery",
	}); err != nil || code != 0 {
		t.Fatalf("repeat recovery reconciliation failed (code %d): %v: %s", code, err, output)
	}
	admins, err := exec.Command("net", "localgroup", "Administrators").CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(admins)), strings.ToLower(username)) {
		t.Fatalf("reconciled recovery account is not an administrator: %v: %s", err, admins)
	}
}

func TestVMReadOnlyEndpointOperations(t *testing.T) {
	if os.Getenv("WARDEN_VM_INTEGRATION") != "1" {
		t.Skip("set WARDEN_VM_INTEGRATION=1 on a disposable elevated Windows VM")
	}
	if code, output, err := runCmdJob(map[string]interface{}{"cmd_type": "system_info"}); err != nil || code != 0 || !strings.Contains(output, "OsName") {
		t.Fatalf("system information command failed (code %d): %v: %s", code, err, output)
	}
	if code, output, err := listDirectory(map[string]interface{}{"path": "::folders::"}); err != nil || code != 0 {
		t.Fatalf("directory roots failed (code %d): %v: %s", code, err, output)
	} else {
		var listing map[string]interface{}
		if json.Unmarshal([]byte(output), &listing) != nil || listing["path"] != "::folders::" {
			t.Fatalf("invalid directory listing: %s", output)
		}
	}
	for _, check := range []string{"firewall_enabled", "antivirus_present", "guest_account_disabled"} {
		result := runComplianceCheck(check)
		if result.Check != check || result.Status == "" {
			t.Fatalf("invalid compliance result for %s: %#v", check, result)
		}
	}
}

func TestVMManagedFirewallLifecycle(t *testing.T) {
	if os.Getenv("WARDEN_VM_INTEGRATION") != "1" {
		t.Skip("set WARDEN_VM_INTEGRATION=1 on a disposable elevated Windows VM")
	}
	const raw = `[{"name":"VM integration allow","direction":"in","action":"allow","protocol":"tcp","local_ports":["65530"],"profiles":["private"]}]`
	defer func() {
		if err := clearPolicySetting("windows_firewall_rules"); err != nil {
			t.Errorf("firewall cleanup failed: %v", err)
		}
	}()
	if code, output, err := applyPolicySettings(map[string]interface{}{"windows_firewall_rules": raw}); err != nil || code != 0 {
		t.Fatalf("apply firewall policy failed (code %d): %v: %s", code, err, output)
	}
	query, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=Warden Managed: VM integration allow").CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(query)), "vm integration allow") {
		t.Fatalf("managed firewall rule was not installed: %v: %s", err, query)
	}
	if code, output, err := checkPolicyDrift([]string{"windows_firewall_rules"}); err != nil || code != 0 || !strings.Contains(output, "VM integration allow") {
		t.Fatalf("firewall drift read-back failed (code %d): %v: %s", code, err, output)
	}
}
