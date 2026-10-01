package main

// security_test.go — focused tests for security-critical logic:
// operation whitelisting, path-traversal protection, and the
// policy-template LGPO scope regression (the /m-vs-/un bug found live on
// real Windows). Windows-only (like the rest of agent-go) — build/run with
// GOOS=windows.

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every operation dispatchJob can route to must also be in
// operationWhitelist — dispatchJob checks the whitelist before the switch,
// so a name present in the switch but missing from the whitelist would
// silently be unreachable (not a security bug, but a real "this job type
// doesn't work" footgun). Conversely, every whitelisted name should be
// handled by dispatchJob's switch — an entry with no matching case would
// panic with "unhandled operation" at runtime instead of at build/test time.
func TestOperationWhitelistMatchesDispatchSwitch(t *testing.T) {
	knownOperations := []string{
		"INSTALL_APP", "UNINSTALL_APP", "CREATE_USER", "PROVISION_WARDEN_IDENTITY", "WARDEN_ONLY_LOCKDOWN", "DELETE_USER",
		"RESET_PASSWORD", "DISABLE_USER", "ENABLE_USER", "GRANT_ELEVATION",
		"REVOKE_ELEVATION", "RUN_CMD", "REBOOT", "SHUTDOWN",
		"COLLECT_SYSINFO", "COLLECT_SOFTWARE", "UPDATE_AGENT",
		"SET_PERIPHERAL_POLICY", "SETUP_REMOTE_ACCESS", "REMOVE_REMOTE_ACCESS",
		"COMPLIANCE_SCAN", "FILE_PUSH", "FILE_PULL", "LIST_DIRECTORY", "GET_EVENT_LOGS",
		"WINDOWS_UPDATE", "UNINSTALL_AGENT", "REINSTALL_AGENT", "PUSH_LOCAL_POLICY",
		"CHECK_POLICY_DRIFT", "COLLECT_USERS",
		"ROTATE_TLS_PINS",
		"CONFIGURE_DEVICE_IDENTITY",
		"CAPTURE_PACKETS",
		"COLLECT_NETWORK_FLOWS",
		"SYNC_WARDEN_HOME",
		"WARDEN_HOME_HISTORY",
		"APPLY_DEVICE_EXPERIENCE",
		"ENABLE_BITLOCKER", "ROTATE_BITLOCKER_RECOVERY",
		"ENABLE_BITLOCKER",
		"ROTATE_BITLOCKER_RECOVERY",
	}
	for _, op := range knownOperations {
		if !operationWhitelist[op] {
			t.Errorf("operation %q is dispatched but missing from operationWhitelist", op)
		}
	}
	for op := range operationWhitelist {
		found := false
		for _, k := range knownOperations {
			if k == op {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("operationWhitelist has %q but this test doesn't know about it — "+
				"update knownOperations (and verify dispatchJob's switch actually handles it)", op)
		}
	}
}

func TestManagedIdentityPreservesExistingNetworkLogonDenyList(t *testing.T) {
	input := "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\nSeDenyNetworkLogonRight = *S-1-5-32-546\r\n[Version]\r\n"
	got, err := addDeniedNetworkLogonSID(input, "S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "*S-1-5-32-546,*S-1-5-21-1-2-3-1001") {
		t.Fatalf("existing deny entries were not preserved: %s", got)
	}
}

func TestTrustedCommandClockUsesPinnedServerDate(t *testing.T) {
	serverClockMu.Lock()
	oldOffset, oldKnown := serverClockOffset, serverClockKnown
	serverClockOffset, serverClockKnown = 0, false
	serverClockMu.Unlock()
	defer func() {
		serverClockMu.Lock()
		serverClockOffset, serverClockKnown = oldOffset, oldKnown
		serverClockMu.Unlock()
	}()

	serverTime := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	recordServerClock(serverTime.Format(http.TimeFormat), time.Now().Add(-100*time.Millisecond))
	got := trustedCommandUnix()
	if delta := got - serverTime.Unix(); delta < -2 || delta > 2 {
		t.Fatalf("trusted command clock differs from server date by %d seconds", delta)
	}
}

func TestAutomaticClockCorrectionThresholds(t *testing.T) {
	now := time.Now()
	if clockCorrectionNeeded(now.Add(30*time.Second), now) {
		t.Fatal("small drift should not change the system clock")
	}
	if !clockCorrectionNeeded(now.Add(2*time.Minute), now) {
		t.Fatal("material drift should change the system clock")
	}
	if !clockCorrectionNeeded(now.Add(25*time.Hour), now) {
		t.Fatal("authenticated Warden time must repair a badly skewed endpoint clock")
	}
	if !validTimeZoneName("India Standard Time") || validTimeZoneName("UTC\nInjected") {
		t.Fatal("time-zone validation rejected a safe ID or accepted control characters")
	}
}

func TestAgentVersionComparisonPreventsDowngrades(t *testing.T) {
	cases := []struct {
		candidate, current string
		want               int
	}{
		{"2.1.24", "2.1.23", 1},
		{"2.1.23", "2.1.23", 0},
		{"2.1.9", "2.1.10", -1},
	}
	for _, tc := range cases {
		got, err := compareAgentVersions(tc.candidate, tc.current)
		if err != nil || got != tc.want {
			t.Errorf("compareAgentVersions(%q, %q) = %d, %v; want %d", tc.candidate, tc.current, got, err, tc.want)
		}
	}
	if _, err := compareAgentVersions("latest", "2.1.23"); err == nil {
		t.Fatal("ambiguous version label should be rejected")
	}
}

func TestManagedFirewallRulesValidateApplicationIPAndPorts(t *testing.T) {
	raw := `[{"name":"ERP egress","direction":"out","action":"allow","protocol":"tcp","program":"C:\\Program Files\\ERP\\erp.exe","remote_addresses":["10.20.0.0/16","203.0.113.8"],"remote_ports":["443","8000-8010"],"profiles":["domain","private"]}]`
	rules, err := parseManagedFirewallRules(raw)
	if err != nil {
		t.Fatalf("valid firewall policy rejected: %v", err)
	}
	if len(rules) != 1 || rules[0].Program == "" {
		t.Fatalf("unexpected parsed rules: %+v", rules)
	}
}

func TestManagedFirewallRulesRejectInvalidInput(t *testing.T) {
	invalid := []string{
		`[{"name":"Traversal","direction":"out","action":"allow","program":"..\\evil.exe"}]`,
		`[{"name":"Bad address","direction":"in","action":"block","remote_addresses":["not-an-ip"]}]`,
		`[{"name":"Bad port","direction":"out","action":"block","remote_ports":["70000"]}]`,
		`[{"name":"Block all egress","direction":"out","action":"block"}]`,
		`[{"name":"Block Warden","direction":"out","action":"block","program":"C:\\Program Files\\WardenAgent\\warden-agent.exe"}]`,
	}
	for _, raw := range invalid {
		if _, err := parseManagedFirewallRules(raw); err == nil {
			t.Errorf("invalid firewall policy accepted: %s", raw)
		}
	}
}

func TestDisplayIconExecutable(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"quoted icon index", `"C:\Program Files\Acme\acme.exe",0`, `C:\Program Files\Acme\acme.exe`},
		{"plain executable", `C:\Apps\tool.exe`, `C:\Apps\tool.exe`},
		{"non executable icon", `C:\Apps\tool.dll,2`, ""},
		{"relative path", `tool.exe`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := displayIconExecutable(test.input); got != test.want {
				t.Fatalf("displayIconExecutable(%q) = %q; want %q", test.input, got, test.want)
			}
		})
	}
}

func TestDispatchJobRejectsUnknownOperation(t *testing.T) {
	env := &Envelope{JobID: "test", Operation: "DELETE_ENTIRE_DISK", Payload: nil}
	code, _, err := dispatchJob(env, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an unwhitelisted operation, got nil")
	}
	if code == 0 {
		t.Fatal("expected a nonzero exit code for a rejected operation")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected a 'not allowed' error message, got: %v", err)
	}
}

func TestDownloadURLMustUsePinnedWardenOrigin(t *testing.T) {
	cfgMu.Lock()
	previous := cfg
	cfg.ServerURL = "https://warden.example.test"
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		cfg = previous
		cfgMu.Unlock()
	}()

	if _, err := validatePinnedDownloadURL("https://warden.example.test/api/agent/apps/1/download"); err != nil {
		t.Fatalf("same-origin HTTPS URL rejected: %v", err)
	}
	for _, raw := range []string{
		"http://warden.example.test/api/agent/apps/1/download",
		"https://evil.example.test/payload.exe",
		"https://user:password@warden.example.test/payload.exe",
	} {
		if _, err := validatePinnedDownloadURL(raw); err == nil {
			t.Errorf("unsafe download URL was accepted: %s", raw)
		}
	}
}

func TestEnvelopeBindingRejectsCrossTenantOrEndpointCommands(t *testing.T) {
	current := AgentConfig{CompanyID: "tenant-a", EndpointID: "endpoint-a"}
	if err := validateEnvelopeBinding(&Envelope{CompanyID: "tenant-a", EndpointID: "endpoint-a"}, current); err != nil {
		t.Fatalf("matching binding rejected: %v", err)
	}
	for _, env := range []Envelope{
		{CompanyID: "tenant-b", EndpointID: "endpoint-a"},
		{CompanyID: "tenant-a", EndpointID: "endpoint-b"},
		{},
	} {
		if err := validateEnvelopeBinding(&env, current); err == nil {
			t.Fatalf("invalid binding accepted: %+v", env)
		}
	}
}

// resolveAllowedPath is the only thing standing between FILE_PUSH/FILE_PULL
// and writing/reading anywhere on disk a job payload asks for. These cases
// specifically target the failure modes a naive prefix-string-match
// implementation would get wrong (which is why this uses filepath.Rel
// instead of strings.HasPrefix — a bare prefix check would let
// "c:\programdata\wardenagentevil" pass a check against
// "c:\programdata\wardenagent").
func TestResolveAllowedPathTraversal(t *testing.T) {
	roots := []string{`c:\programdata\wardenagent\`, `c:\windows\temp\`}

	allowed := []string{
		`C:\ProgramData\WardenAgent\staging\foo.txt`,
		`c:\windows\temp\bar.log`,
	}
	for _, p := range allowed {
		if _, err := resolveAllowedPath(p, roots); err != nil {
			t.Errorf("expected %q to be allowed, got error: %v", p, err)
		}
	}

	rejected := []string{
		`C:\ProgramData\WardenAgent\..\..\Windows\System32\evil.dll`,
		`c:\windows\temp\..\system32\evil.txt`,
		`C:\ProgramData\WardenAgentEvil\foo.txt`, // sibling dir with matching prefix string
		`C:\Windows\System32\config\SAM`,
		`relative\path.txt`, // not absolute at all
	}
	for _, p := range rejected {
		if resolved, err := resolveAllowedPath(p, roots); err == nil {
			t.Errorf("expected %q to be rejected, got resolved path %q", p, resolved)
		}
	}
}

func TestCanonicalPathCleansTraversalSegments(t *testing.T) {
	// canonicalPath walks up to the nearest existing ancestor and rebuilds
	// the path from there — this test only checks the pure string-cleaning
	// behavior for a path whose full chain exists (C:\ always does), not
	// the symlink-resolution branch (untestable without a real filesystem).
	resolved, err := canonicalPath(`C:\ProgramData\..\ProgramData\WardenAgent\..\WardenAgent\x.txt`)
	if err != nil {
		t.Fatalf("canonicalPath failed: %v", err)
	}
	want := filepath.Clean(`C:\ProgramData\WardenAgent\x.txt`)
	if !strings.EqualFold(resolved, want) {
		t.Errorf("canonicalPath = %q, want %q", resolved, want)
	}
}

// Regression test for the live-discovered bug: PUSH_LOCAL_POLICY's
// restrict-standard-user-tools template was originally hardcoded to apply
// via LGPO.exe's /m (machine/Computer) scope. Verified live on real
// Windows that this writes to HKLM, disabling Task Manager/regedit for
// EVERY account including Administrators — directly contradicting the
// template's own description ("for standard (non-admin) users"). The fix
// added a per-template lgpoFlag; this test guards against it silently
// reverting to /m again.
func TestPolicyTemplateLGPOFlags(t *testing.T) {
	cases := map[string]string{
		"restrict-standard-user-tools":   "/un",
		"applocker-pin-warden-publisher": "/m",
		"firewall-scope-agent-egress":    "/m",
	}
	for template, wantFlag := range cases {
		spec, ok := policyTemplates[template]
		if !ok {
			t.Errorf("expected template %q to exist in policyTemplates", template)
			continue
		}
		if spec.lgpoFlag != wantFlag {
			t.Errorf("template %q: lgpoFlag = %q, want %q (regression: this is the exact "+
				"live-confirmed bug where /m disabled Task Manager machine-wide instead of "+
				"just for Non-Administrators)", template, spec.lgpoFlag, wantFlag)
		}
	}
	if policyTemplates["restrict-standard-user-tools"].lgpoFlag == "/m" {
		t.Fatal("restrict-standard-user-tools must NEVER use /m — verified live that this " +
			"disables Task Manager/regedit for Administrators too, not just standard users")
	}
}

// Regression test for the tamper.go SDDL ordering fix: SYSTEM's ALLOW ACE
// must appear BEFORE the AU/BA DENY ACEs in the locked SDDL string, since
// Windows AccessCheck resolves ACEs in the order they appear (not
// "all denies first") — verified live that this ordering is what lets
// SYSTEM unlock/stop the service while an Administrator remains denied.
// Also checks the owner is pinned to SYSTEM (O:SYG:SY) and that SYSTEM's
// ACE grants WD (WRITE_DAC) and SD (DELETE), both required for the
// sanctioned self-removal flow to work without relying on implicit
// owner rights.
func TestLockedServiceSDDLOrderingAndRights(t *testing.T) {
	sddl := lockedServiceSDDL

	if !strings.HasPrefix(sddl, "O:SYG:SY") {
		t.Fatalf("lockedServiceSDDL must pin owner+group to SYSTEM (O:SYG:SY), got prefix of: %.20s", sddl)
	}

	syAllowIdx := strings.Index(sddl, ";;;SY)")
	auDenyIdx := strings.Index(sddl, ";;;AU)")
	baDenyIdx := strings.Index(sddl, ";;;BA)")
	if syAllowIdx == -1 || auDenyIdx == -1 || baDenyIdx == -1 {
		t.Fatalf("lockedServiceSDDL missing an expected SY/AU/BA ACE: %s", sddl)
	}
	if syAllowIdx > auDenyIdx || syAllowIdx > baDenyIdx {
		t.Fatalf("SYSTEM's ALLOW ACE must appear before the AU/BA DENY ACEs "+
			"(Windows AccessCheck resolves ACEs in list order, not deny-first) — "+
			"got SY at %d, AU at %d, BA at %d in: %s", syAllowIdx, auDenyIdx, baDenyIdx, sddl)
	}

	// Extract the rights string between "(A;;" and ";;;SY)" for SYSTEM's ACE.
	start := strings.Index(sddl, "(A;;")
	end := strings.Index(sddl, ";;;SY)")
	if start == -1 || end == -1 || end < start {
		t.Fatalf("could not locate SYSTEM's ALLOW ACE rights in: %s", sddl)
	}
	syRights := sddl[start+len("(A;;") : end]
	// mgr.OpenService requests SERVICE_ALL_ACCESS. DC (change config) and WO
	// (write owner), alongside the existing standard rights, are therefore
	// required even though the helper only proceeds to issue STOP/QUERY.
	for _, want := range []string{"WD", "SD", "DC", "WO"} {
		if !strings.Contains(syRights, want) {
			t.Errorf("SYSTEM's ACE rights %q missing %q (needed to unlock/delete without "+
				"relying on implicit owner rights)", syRights, want)
		}
	}
}

func TestLockedServiceNeverGrantsAdministratorsMutationRights(t *testing.T) {
	if strings.Contains(lockedServiceSDDL, ";;;BA)") && strings.Contains(lockedServiceSDDL, "(A;;") {
		for _, ace := range strings.Split(lockedServiceSDDL, "(") {
			if strings.HasPrefix(ace, "A;;") && strings.Contains(ace, ";;;BA)") {
				t.Fatalf("locked service ACL must not grant Administrators any service rights: %s", lockedServiceSDDL)
			}
		}
	}
	for _, principal := range []string{";;;BA)", ";;;AU)"} {
		if !strings.Contains(lockedServiceSDDL, "(D;;WPDTCC"+principal) {
			t.Fatalf("locked service ACL must explicitly deny stop/pause/config-query to %s: %s", principal, lockedServiceSDDL)
		}
	}
}

func TestSelfRemovalAllowsResultReportBeforeStoppingService(t *testing.T) {
	delay := strings.Index(reaperScriptTemplate, "ping -n 6")
	stop := strings.Index(reaperScriptTemplate, `sc stop "%s"`)
	if delay == -1 || stop == -1 || delay > stop {
		t.Fatalf("self-removal must delay service stop long enough to report its signed job result")
	}
}
