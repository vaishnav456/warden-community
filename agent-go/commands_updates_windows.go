package main

import (
	"fmt"
	"strconv"
	"strings"
)

// ── Update agent ──────────────────────────────────────────────────────────────

func updateAgent(jobID string, p map[string]interface{}, _ logFn) (int, string, error) {
	version, _ := p["version"].(string)
	if cmp, err := compareAgentVersions(version, agentVersion); err != nil {
		return 1, "", fmt.Errorf("invalid update version: %w", err)
	} else if cmp <= 0 {
		return 0, fmt.Sprintf("Update skipped: installed version %s is not older than %s", agentVersion, version), nil
	}

	// Use the same persistent SYSTEM Scheduled Task handoff as a full agent
	// reinstall. A child cmd.exe can be terminated with the Windows service,
	// which strands the endpoint between stop, replacement and rollback. The
	// scheduled helper survives service shutdown and reboot, verifies both
	// artifacts again, waits for a version-specific health marker, and restores
	// the previous binary and Credential Provider if startup fails.
	return prepareAgentReinstall(jobID, p)
}

func compareAgentVersions(a, b string) (int, error) {
	parse := func(value string) ([3]int, error) {
		var result [3]int
		parts := strings.Split(strings.TrimSpace(value), ".")
		if len(parts) != 3 {
			return result, fmt.Errorf("version %q must be major.minor.patch", value)
		}
		for i, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 {
				return result, fmt.Errorf("version %q contains a non-numeric component", value)
			}
			result[i] = n
		}
		return result, nil
	}
	av, err := parse(a)
	if err != nil {
		return 0, err
	}
	bv, err := parse(b)
	if err != nil {
		return 0, err
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1, nil
		}
		if av[i] > bv[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func rotateTLSPins(p map[string]interface{}) (int, string, error) {
	raw, ok := p["fingerprints"].([]interface{})
	if !ok || len(raw) == 0 || len(raw) > 3 {
		return 1, "", fmt.Errorf("fingerprints must contain between 1 and 3 SHA-256 values")
	}
	values := make([]string, 0, len(raw))
	newSet := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		value, ok := item.(string)
		if !ok {
			return 1, "", fmt.Errorf("fingerprints must be strings")
		}
		fp, err := normalizeFingerprint(value)
		if err != nil {
			return 1, "", err
		}
		if _, exists := newSet[fp]; !exists {
			newSet[fp] = struct{}{}
			values = append(values, fp)
		}
	}
	overlap := false
	for fp := range currentPinnedFingerprints() {
		if _, ok := newSet[fp]; ok {
			overlap = true
			break
		}
	}
	if !overlap {
		return 1, "", fmt.Errorf("new TLS pin set must overlap the currently trusted set")
	}
	c := getConfig()
	c.CertFingerprints = values
	c.CertFingerprint = values[0]
	if err := saveConfig(c); err != nil {
		return 1, "", err
	}
	if err := replacePinnedFingerprints(values); err != nil {
		return 1, "", err
	}
	return 0, fmt.Sprintf("Installed %d TLS certificate pin(s)", len(values)), nil
}
