package main

import "testing"

func TestWorkspaceActivityColorsNeverClaimUnverifiedRecording(t *testing.T) {
	for _, c := range []struct {
		known bool
		state workspaceActivity
		want  string
	}{
		{false, workspaceActivity{RemoteActive: true}, "STATUS UNKNOWN"},
		{true, workspaceActivity{}, "WARDEN"},
		{true, workspaceActivity{RemoteActive: true}, "REMOTE ACTIVE"},
		{true, workspaceActivity{RemoteActive: true, RecordingActive: true}, "REMOTE ACTIVE"},
		{true, workspaceActivity{RemoteActive: true, RecordingActive: true, RecordingSupported: true}, "RECORDING"},
	} {
		if got := workspaceActivityLabel(c.known, c.state); got != c.want {
			t.Fatalf("activity %+v: %s", c.state, got)
		}
	}
}
