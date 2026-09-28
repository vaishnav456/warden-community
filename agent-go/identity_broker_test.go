package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func brokerRequest(t *testing.T, username, password string) []byte {
	t.Helper()
	raw, err := json.Marshal(identityBrokerRequest{Version: 1, Username: username, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIdentityBrokerValidatesRequestsBeforeAuthentication(t *testing.T) {
	called := false
	response := handleIdentityBrokerRequest(
		brokerRequest(t, `bad\name`, "secret"),
		func(_, _ string) (identityBrokerResponse, error) {
			called = true
			return identityBrokerResponse{}, nil
		},
	)
	if called {
		t.Fatal("authenticator was called for an invalid username")
	}
	if response.OK || response.Message == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestIdentityBrokerReturnsCanonicalSuccessfulIdentity(t *testing.T) {
	response := handleIdentityBrokerRequest(
		brokerRequest(t, "Jane", "Secret!123456"),
		func(username, password string) (identityBrokerResponse, error) {
			if username != "Jane" || password != "Secret!123456" {
				t.Fatalf("unexpected credentials passed to authenticator")
			}
			return identityBrokerResponse{OK: true, Username: "jane", LocalPassword: "DeviceOnly!Aa1"}, nil
		},
	)
	if !response.OK || response.Username != "jane" || response.LocalPassword == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestIdentityBrokerAcceptsEmailAndReturnsLocalAccount(t *testing.T) {
	response := handleIdentityBrokerRequest(
		brokerRequest(t, "jane.doe@example.com", "Secret!123456"),
		func(username, password string) (identityBrokerResponse, error) {
			if username != "jane.doe@example.com" || password != "Secret!123456" {
				t.Fatalf("unexpected credentials passed to authenticator")
			}
			return identityBrokerResponse{OK: true, Username: "jane-abc123", LocalPassword: "DeviceOnly!Aa1"}, nil
		},
	)
	if !response.OK || response.Username != "jane-abc123" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestIdentityBrokerRejectsSuccessWithoutDeviceCredential(t *testing.T) {
	response := handleIdentityBrokerRequest(
		brokerRequest(t, "jane", "Secret!123456"),
		func(_, _ string) (identityBrokerResponse, error) {
			return identityBrokerResponse{OK: true, Username: "jane"}, nil
		},
	)
	if response.OK || response.Message == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestIdentityBrokerDoesNotEchoPasswordOnFailure(t *testing.T) {
	password := "NeverEchoThis!123"
	response := handleIdentityBrokerRequest(
		brokerRequest(t, "jane", password),
		func(_, _ string) (identityBrokerResponse, error) {
			return identityBrokerResponse{}, errors.New("network down")
		},
	)
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), password) {
		t.Fatal("broker response exposed the password")
	}
	if response.OK || response.Message == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestIdentityBrokerFrameRoundTrip(t *testing.T) {
	payload := brokerRequest(t, "jane", "Secret!123456")
	var framed bytes.Buffer
	if err := writeIdentityBrokerFrame(&framed, payload); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(framed.Bytes()[:4]); got != uint32(len(payload)) {
		t.Fatalf("frame length = %d, want %d", got, len(payload))
	}
	decoded, err := readIdentityBrokerFrame(&framed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("frame payload changed")
	}
}

func TestIdentityBrokerRejectsOversizedFrameBeforeAllocation(t *testing.T) {
	var frame bytes.Buffer
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], identityBrokerMaxFrame+1)
	frame.Write(header[:])
	if _, err := readIdentityBrokerFrame(&frame); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}

func TestManagedIdentityRecoveryRequiresExplicitAuthorization(t *testing.T) {
	if managedIdentityProvisionAllowed(true, false, false) {
		t.Fatal("ordinary provisioning must not adopt an existing unmanaged account")
	}
	if !managedIdentityProvisionAllowed(true, false, true) {
		t.Fatal("explicit recovery must be able to restore a lost device secret")
	}
	if !managedIdentityProvisionAllowed(true, true, false) {
		t.Fatal("an already-managed account must remain repairable")
	}
}
