package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os/exec"
	"strconv"
	"strings"
)

// ── Compliance scan ───────────────────────────────────────────────────────────

func complianceScan(jobID string, p map[string]interface{}) (int, string, error) {
	checks := []string{
		"bitlocker_enabled", "firewall_enabled", "antivirus_present",
		"screen_lock_enabled", "auto_update_enabled",
		"password_min_length", "guest_account_disabled",
	}
	if raw, ok := p["checks"].([]interface{}); ok && len(raw) > 0 {
		checks = nil
		for _, c := range raw {
			if s, ok := c.(string); ok {
				checks = append(checks, s)
			}
		}
	}

	type checkResult struct {
		Check  string `json:"check"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	var results []checkResult
	for _, name := range checks {
		results = append(results, runComplianceCheck(name))
	}

	passed := 0
	for _, r := range results {
		if r.Status == "pass" {
			passed++
		}
	}
	total := len(results)
	score := 0
	if total > 0 {
		score = passed * 100 / total
	}
	overall := "non_compliant"
	if passed == total {
		overall = "compliant"
	}

	policyID, _ := p["policy_id"].(string)
	// Unlike getEventLogs/filePull, the full results are also returned in
	// log_output below as a fallback, so a POST failure here doesn't lose
	// the data outright -- but it does mean the dedicated compliance_results
	// table (and anything reading from it, e.g. the compliance dashboard)
	// silently misses this scan. Surface the error in the log rather than
	// discarding it, without failing the job since the scan itself succeeded.
	postNote := ""
	if _, err := apiPostAuth("/api/agent/compliance-result", map[string]interface{}{
		"job_id":             jobID,
		"policy_id":          policyID,
		"policy_fingerprint": p["policy_fingerprint"],
		"overall_status":     overall,
		"score":              score,
		"results":            results,
	}); err != nil {
		postNote = fmt.Sprintf(" (warning: failed to report to compliance dashboard: %v)", err)
	}

	b, _ := json.Marshal(map[string]interface{}{
		"overall_status": overall,
		"score":          score,
		"results":        results,
	})
	return 0, string(b) + postNote, nil
}

func runComplianceCheck(name string) struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
} {
	type R = struct {
		Check  string `json:"check"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	pass := func(d string) R { return R{name, "pass", d} }
	fail := func(d string) R { return R{name, "fail", d} }
	errR := func(d string) R { return R{name, "error", d} }

	switch name {
	case "bitlocker_enabled":
		out, err := exec.Command("manage-bde", "-status", "C:").Output()
		if err != nil {
			return errR("manage-bde failed")
		}
		s := string(out)
		if strings.Contains(s, "Protection On") {
			return pass("BitLocker is enabled")
		}
		return fail("BitLocker is not enabled on C:")

	case "firewall_enabled":
		out, err := exec.Command("powershell", "-NonInteractive", "-Command",
			"(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Count").Output()
		if err != nil {
			return errR("Get-NetFirewallProfile failed")
		}
		cnt := strings.TrimSpace(string(out))
		if cnt == "0" || cnt == "" {
			return pass("All firewall profiles enabled")
		}
		return fail(cnt + " firewall profile(s) disabled")

	case "antivirus_present":
		out, err := exec.Command("powershell", "-NonInteractive", "-Command",
			"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ConvertTo-Json").Output()
		if err != nil {
			return errR("Get-CimInstance failed")
		}
		s := strings.TrimSpace(string(out))
		if s != "" && s != "null" && s != "[]" {
			if len(s) > 200 {
				s = s[:200]
			}
			return pass(s)
		}
		return fail("No antivirus product detected")

	case "screen_lock_enabled":
		k, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.QUERY_VALUE)
		if err != nil {
			return errR("registry open failed")
		}
		defer k.Close()
		timeoutStr, _, _ := k.GetStringValue("ScreenSaveTimeOut")
		secure, _, _ := k.GetStringValue("ScreenSaverIsSecure")
		timeoutSec, _ := strconv.Atoi(timeoutStr)
		timeoutMin := timeoutSec / 60
		if secure == "1" && timeoutMin <= 15 && timeoutMin > 0 {
			return pass(fmt.Sprintf("Screen lock: %dmin, secure=1", timeoutMin))
		}
		return fail(fmt.Sprintf("Screen lock: %dmin, secure=%s", timeoutMin, secure))

	case "auto_update_enabled":
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, registry.QUERY_VALUE)
		if err != nil {
			return pass("Auto update enabled (no policy override)")
		}
		defer k.Close()
		noAuto, _, _ := k.GetIntegerValue("NoAutoUpdate")
		if noAuto == 0 {
			return pass("Auto update enabled")
		}
		return fail("Auto update disabled by policy")

	case "password_min_length":
		out, _ := exec.Command("net", "accounts").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Minimum password length") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					minLen, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
					if minLen >= 8 {
						return pass(fmt.Sprintf("Minimum password length: %d", minLen))
					}
					return fail(fmt.Sprintf("Minimum password length: %d (requires >=8)", minLen))
				}
			}
		}
		return errR("could not determine password policy")

	case "guest_account_disabled":
		out, _ := exec.Command("net", "user", "Guest").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Account active") {
				if strings.Contains(line, "Yes") {
					return fail("Guest account is active")
				}
				return pass("Guest account disabled")
			}
		}
		return pass("Guest account not found (assumed disabled)")

	default:
		return errR(fmt.Sprintf("Unknown check: %s", name))
	}
}
