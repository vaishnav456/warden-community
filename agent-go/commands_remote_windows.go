package main

import (
	"fmt"
	"net/url"
	"strings"
)

// ── Remote access ─────────────────────────────────────────────────────────────

func setupRemoteAccess(_ string, p map[string]interface{}) (int, string, error) {
	relayURL, _ := p["relay_url"].(string)
	if relayURL == "" {
		return 1, "", fmt.Errorf("missing relay_url in payload")
	}
	// All the validation/rejection paths below return before ever reaching
	// runRelaySession's goroutine — reportRelayFailure only used to be
	// called from failures WITHIN that goroutine, so a rejection here
	// (e.g. "already running", the most common one: a previous session's
	// goroutine hasn't finished tearing down yet when a second
	// SETUP_REMOTE_ACCESS lands moments later) left the browser side with
	// no report at all, stuck showing "Waiting for device..." for the
	// full 60s ws_proxy timeout instead of learning the real reason in
	// seconds. Report every failure path here too, not just the async ones.
	sessionID := sessionIDFromRelayURL(relayURL)
	fail := func(reason string, err error) (int, string, error) {
		reportRelayFailure(sessionID, reason)
		return 1, "", err
	}
	if apiKey == "" {
		return fail("agent API key not loaded", fmt.Errorf("agent API key not loaded"))
	}
	consentRequired, _ := p["consent_required"].(bool)
	consentTitle, _ := p["consent_title"].(string)
	consentMessage, _ := p["consent_message"].(string)
	requestedAccess := make([]string, 0, 6)
	if raw, ok := p["requested_access"].([]interface{}); ok {
		for _, item := range raw {
			if label, ok := item.(string); ok && strings.TrimSpace(label) != "" {
				requestedAccess = append(requestedAccess, strings.TrimSpace(label))
			}
		}
	}
	if consentRequired {
		helperName, _ := p["helper_name"].(string)
		reason, _ := p["reason"].(string)
		if helperName == "" {
			helperName = "A Warden technician"
		}
		if reason == "" {
			reason = "Interactive support"
		}
		if err := requestRemoteConsent(sessionID, helperName, reason, consentTitle, consentMessage, requestedAccess); err != nil {
			return fail(err.Error(), err)
		}
	} else {
		reportRemoteConsent(sessionID, "not_required")
	}
	parsed, err := url.Parse(relayURL)
	if err != nil {
		return fail(fmt.Sprintf("invalid relay_url: %v", err), fmt.Errorf("invalid relay_url: %w", err))
	}
	server, err := url.Parse(serverURL())
	if err != nil {
		return fail(fmt.Sprintf("invalid configured server URL: %v", err), fmt.Errorf("invalid configured server URL: %w", err))
	}
	if parsed.Scheme != "wss" || !strings.EqualFold(
		parsed.Host, server.Host,
	) || parsed.RawQuery != "" || !strings.HasPrefix(
		parsed.Path, "/agent-relay/",
	) {
		return fail("relay_url is not an approved Warden wss URL", fmt.Errorf("relay_url is not an approved Warden wss URL"))
	}
	if err := startRemoteRelay(relayURL, apiKey, "Remote support is connected", consentMessage); err != nil {
		return fail(err.Error(), err)
	}
	return 0, fmt.Sprintf("Remote relay session connecting to %s", relayURL), nil
}

func removeRemoteAccess() (int, string, error) {
	stopRemoteRelay()
	return 0, "Remote access stopped", nil
}
