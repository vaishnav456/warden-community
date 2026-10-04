package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// ── Local user discovery ──────────────────────────────────────────────────
//
// The server has had a /api/agent/users route (routes/agent_api.py's
// report_users()) since the Users tab UI was built, but earlier agent
// implementations never called
// it — CREATE_USER/DELETE_USER/etc. only ever acted on one named account,
// nothing ever reported the actual full list back, so the Users tab has
// never shown real data regardless of what's actually on the machine.

var netUserFieldRe = regexp.MustCompile(`^(.+?)\s{2,}(.+)$`)

// netUserField extracts a labeled field's value from "net user <name>"'s
// detail output, e.g. netUserField(out, "Account active") -> "Yes".
func netUserField(output, label string) string {
	for _, line := range strings.Split(output, "\n") {
		m := netUserFieldRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m != nil && strings.TrimSpace(m[1]) == label {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

// parseNetUserList parses bare "net user"'s columnar username listing
// (several names per line, between a dashed rule and the trailing
// "The command completed successfully." line).
func parseNetUserList(output string) []string {
	var names []string
	inList := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "----"):
			inList = true
		case strings.HasPrefix(line, "The command completed"):
			return names
		case inList && strings.TrimSpace(line) != "":
			names = append(names, strings.Fields(line)...)
		}
	}
	return names
}

// parseNetLocalGroupMembers parses "net localgroup <group>"'s one-name-
// per-line member listing the same way.
func parseNetLocalGroupMembers(output string) map[string]bool {
	members := map[string]bool{}
	inList := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "----"):
			inList = true
		case strings.HasPrefix(line, "The command completed"):
			return members
		case inList:
			if name := strings.TrimSpace(line); name != "" {
				members[name] = true
			}
		}
	}
	return members
}

func classifyWindowsAccount(domain, hostname string) string {
	switch {
	case strings.EqualFold(domain, "AzureAD"):
		return "entra"
	case strings.EqualFold(domain, "MicrosoftAccount"):
		return "microsoft"
	case domain == "" || strings.EqualFold(domain, hostname):
		return "local"
	default:
		return "domain"
	}
}

func collectUsers() (int, string, error) {
	// "net user" (bare) is known to exit non-zero for reasons unrelated to
	// the account listing itself -- e.g. it also tries to resolve the
	// local computer's own NetBIOS name for the "User accounts for \\..."
	// header, and a failure there still prints a completely valid account
	// list followed by "The command completed with one or more errors."
	// and exit code 1. Confirmed live: a real run returned exit 1 with a
	// perfectly parseable list of 5 real accounts. Parse the output
	// regardless of exit code, and only treat this as a real failure if
	// parsing actually yields nothing usable.
	out, cmdErr := exec.Command("net", "user").CombinedOutput()
	usernames := parseNetUserList(string(out))
	if len(usernames) == 0 {
		if cmdErr != nil {
			return 1, string(out), fmt.Errorf("net user: %w", cmdErr)
		}
		return 1, string(out), fmt.Errorf("net user: no accounts parsed from output")
	}

	adminOut, _ := exec.Command("net", "localgroup", "Administrators").CombinedOutput()
	admins := parseNetLocalGroupMembers(string(adminOut))
	adminsFolded := make(map[string]bool, len(admins))
	for name := range admins {
		adminsFolded[strings.ToLower(name)] = true
	}

	type reportedUser struct {
		Username      string `json:"username"`
		DisplayName   string `json:"display_name"`
		SID           string `json:"sid"`
		PrincipalName string `json:"principal_name"`
		AccountType   string `json:"account_type"`
		DomainName    string `json:"domain_name"`
		IsAdmin       bool   `json:"is_admin"`
		IsEnabled     bool   `json:"is_enabled"`
	}
	hostname, _ := os.Hostname()
	var users []reportedUser
	for _, uname := range usernames {
		detailOut, err := exec.Command("net", "user", uname).CombinedOutput()
		if err != nil {
			continue // account may have been deleted between listing and detail lookup
		}
		detail := string(detailOut)
		sid, domain, identityErr := lookupWindowsAccountIdentity(uname)
		if identityErr != nil {
			logWarn("User inventory: could not resolve identity for %s: %v", uname, identityErr)
		}
		principal := uname
		if domain != "" {
			principal = domain + `\` + uname
		}
		users = append(users, reportedUser{
			Username:      uname,
			DisplayName:   netUserField(detail, "Full Name"),
			SID:           sid,
			PrincipalName: principal,
			AccountType:   classifyWindowsAccount(domain, hostname),
			DomainName:    domain,
			IsAdmin:       adminsFolded[strings.ToLower(uname)],
			IsEnabled:     netUserField(detail, "Account active") == "Yes",
		})
	}

	if _, err := apiPostAuth("/api/agent/users", map[string]interface{}{"users": users}); err != nil {
		return 1, "", fmt.Errorf("report users: %w", err)
	}
	return 0, fmt.Sprintf("Reported %d local users", len(users)), nil
}

func grantElevation(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	duration := int64(60)
	if d, ok := p["duration_minutes"].(float64); ok {
		duration = int64(d)
	}
	// Persist the expiry before granting rights. If the process crashes after
	// this write, cleanup has a durable record to revoke; the reverse ordering
	// could leave an untracked permanent administrator.
	if err := recordElevationExpiry(username, duration); err != nil {
		return 1, "", fmt.Errorf("persist elevation expiry: %w", err)
	}
	out, err := exec.Command("net", "localgroup", "Administrators", username, "/add").CombinedOutput()
	if err != nil {
		_ = removeElevationExpiry(username)
		return 1, string(out), fmt.Errorf("grant elevation: %w", err)
	}
	return 0, fmt.Sprintf("Elevation granted to %s for %d minutes", username, duration), nil
}

func revokeElevation(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	if username == "" {
		return 1, "", fmt.Errorf("missing username")
	}
	out, err := exec.Command("net", "localgroup", "Administrators", username, "/delete").CombinedOutput()
	if err != nil {
		return 1, string(out), fmt.Errorf("revoke elevation: %w", err)
	}
	if err := removeElevationExpiry(username); err != nil {
		return 1, string(out), fmt.Errorf("persist elevation revocation: %w", err)
	}
	return 0, fmt.Sprintf("Elevation revoked from %s", username), nil
}
