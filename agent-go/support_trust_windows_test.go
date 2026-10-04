package main

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestHelpdeskPipeOwnershipRequiresSystem(t *testing.T) {
	for _, item := range []struct {
		sddl    string
		trusted bool
	}{{"O:SYD:P(A;;GA;;;SY)", true}, {"O:BAD:P(A;;GA;;;BA)", false}, {"O:BUD:P(A;;GA;;;BU)", false}} {
		descriptor, err := windows.SecurityDescriptorFromString(item.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if supportServerOwnerTrusted(descriptor) != item.trusted {
			t.Fatalf("invalid owner trust: %s", item.sddl)
		}
	}
	if supportServerOwnerTrusted(nil) {
		t.Fatal("nil descriptor trusted")
	}
}
func TestHelpdeskConnectionRetryDoesNotBypassAccessChecks(t *testing.T) {
	if !supportConnectionRetryable(windows.ERROR_PIPE_BUSY) || !supportConnectionRetryable(windows.ERROR_FILE_NOT_FOUND) {
		t.Fatal("transient connection not retried")
	}
	if supportConnectionRetryable(windows.ERROR_ACCESS_DENIED) || supportConnectionRetryable(nil) {
		t.Fatal("unsafe retry")
	}
}
