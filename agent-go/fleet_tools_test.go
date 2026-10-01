package main

import (
	"strings"
	"testing"
	"time"
)

func TestBranchTrafficPolicyBoundsAndUTCWindows(t *testing.T) {
	policy := branchTraffic{BusinessStart: 22, BusinessEnd: 6, BusinessKBPS: 16, OffhoursKBPS: 1024}
	if !policy.valid() {
		t.Fatal("valid policy rejected")
	}
	if policy.bytesPerSecond(time.Date(2026, 10, 1, 23, 0, 0, 0, time.UTC)) != 16*1024 {
		t.Fatal("overnight business window ignored")
	}
	if policy.bytesPerSecond(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)) != 1024*1024 {
		t.Fatal("off-hours limit ignored")
	}
	policy.BusinessKBPS = 0
	if policy.valid() {
		t.Fatal("zero limit accepted")
	}
}
func TestSupportMessageCannotBecomeCommandOrCredentialChannel(t *testing.T) {
	for _, message := range []string{"", strings.Repeat("x", 2001), "hello\x00hidden", "hello\rhidden"} {
		if validateSupportMessage(message) == nil {
			t.Fatal("invalid message accepted")
		}
	}
	for _, message := range []string{"My application is frozen", "line one\nline two", "=ordinary description"} {
		if err := validateSupportMessage(message); err != nil {
			t.Fatal(err)
		}
	}
}
