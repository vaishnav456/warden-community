package main

import "testing"

func TestDeviceIdentityRestartIsExplicitOptIn(t *testing.T) {
	for _, value := range []interface{}{nil, false, "true", 1} {
		if deviceIdentityRestartRequested(map[string]interface{}{"restart": value}) {
			t.Fatalf("unexpected restart for %v", value)
		}
	}
	if deviceIdentityRestartRequested(map[string]interface{}{}) {
		t.Fatal("missing restart option must not restart")
	}
	if !deviceIdentityRestartRequested(map[string]interface{}{"restart": true}) {
		t.Fatal("explicit opt-in must be recognized")
	}
}
