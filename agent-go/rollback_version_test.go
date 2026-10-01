package main

import "testing"

func TestSignedRollbackVersionRequiresExactInstalledOrigin(t *testing.T) {
	for _, origin := range []interface{}{nil, "wrong", "2.6.47", true, []interface{}{"invalid"}} {
		if err := validateReinstallVersion("2.6.47", map[string]interface{}{"rollback_from": origin}); err == nil {
			t.Fatal("downgrade accepted without exact origin", origin)
		}
	}
	if err := validateReinstallVersion("2.6.47", map[string]interface{}{"rollback_from": agentVersion}); err != nil {
		t.Fatal("explicit rollback rejected", err)
	}
	if err := validateReinstallVersion(agentVersion, nil); err != nil {
		t.Fatal("repairing same version rejected", err)
	}
	if err := validateReinstallVersion("99.0.0", nil); err != nil {
		t.Fatal("upgrade rejected", err)
	}
	if err := validateReinstallVersion("invalid", map[string]interface{}{"rollback_from": agentVersion}); err == nil {
		t.Fatal("invalid version accepted")
	}
}
