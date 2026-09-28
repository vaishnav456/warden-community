package main

import "testing"

func TestReconnectConfigPreservesInstallationIdentity(t *testing.T) {
	current := AgentConfig{
		InstallationID: "0123456789abcdef0123456789abcdef",
		EndpointID:     "old-endpoint",
		CompanyID:      "old-company",
	}
	bootstrap := AgentConfig{
		ServerURL:           "https://warden.example.test",
		ServerEd25519Pubkey: "new-signing-key",
		CertFingerprint:     "new-cert-pin",
		CompanyID:           "new-company",
		BranchID:            "new-branch",
		EnrollmentToken:     "fresh-token",
	}

	got, err := reconnectConfig(current, bootstrap)
	if err != nil {
		t.Fatalf("reconnectConfig returned error: %v", err)
	}
	if got.InstallationID != current.InstallationID {
		t.Fatalf("installation identity changed: got %q", got.InstallationID)
	}
	if got.EndpointID != "" {
		t.Fatalf("old endpoint id was retained: %q", got.EndpointID)
	}
	if got.CompanyID != bootstrap.CompanyID || got.BranchID != bootstrap.BranchID {
		t.Fatalf("new tenant scope was not applied: %#v", got)
	}
	if got.EnrollmentToken != bootstrap.EnrollmentToken {
		t.Fatal("fresh enrollment token was not retained")
	}
}

func TestReconnectConfigRejectsInstallerWithoutToken(t *testing.T) {
	_, err := reconnectConfig(
		AgentConfig{InstallationID: "0123456789abcdef0123456789abcdef"},
		AgentConfig{ServerURL: "https://warden.example.test", ServerEd25519Pubkey: "key", CertFingerprint: "pin"},
	)
	if err == nil {
		t.Fatal("expected missing token to be rejected")
	}
}

func TestServiceDisplayNameCanBeBrandedWithoutRenamingService(t *testing.T) {
	original := buildServiceDisplayNameB64
	t.Cleanup(func() { buildServiceDisplayNameB64 = original })
	buildServiceDisplayNameB64 = "RXhhbXBsZSBDb250cm9sIEVuZHBvaW50IEFnZW50"
	if got := serviceDisplayName(); got != "Example Control Endpoint Agent" {
		t.Fatalf("serviceDisplayName() = %q", got)
	}
	if serviceName != "WardenAgent" {
		t.Fatalf("stable service identifier changed: %q", serviceName)
	}
	buildServiceDisplayNameB64 = "not valid base64!"
	if got := serviceDisplayName(); got != "Warden Endpoint Agent" {
		t.Fatalf("invalid branding did not fail safely: %q", got)
	}
}
