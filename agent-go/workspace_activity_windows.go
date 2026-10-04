package main

import (
	"sync"
	"time"
	"unsafe"
)

type workspaceActivity struct {
	RemoteActive       bool `json:"remote_active"`
	RecordingActive    bool `json:"recording_active"`
	RecordingSupported bool `json:"recording_supported"`
}
type workspaceActivityPoll struct {
	mu          sync.Mutex
	pending     workspaceActivity
	known, busy bool
}

func currentWorkspaceActivity() workspaceActivity {
	relayMu.Lock()
	session, connected := relayLive, relayConn != nil
	relayMu.Unlock()
	active := session != nil && connected
	if active {
		select {
		case <-session.stop:
			active = false
		default:
		}
	}
	// No video recorder exists yet. Never label screen capture as recording.
	return workspaceActivity{RemoteActive: active, RecordingSupported: false}
}
func workspaceActivityLabel(known bool, state workspaceActivity) string {
	if !known {
		return "STATUS UNKNOWN"
	}
	if state.RecordingSupported && state.RecordingActive {
		return "RECORDING"
	}
	if state.RemoteActive {
		return "REMOTE ACTIVE"
	}
	return "WARDEN"
}
func (p *floatingWorkspace) pollActivity() {
	p.activityPoll.mu.Lock()
	if p.activityPoll.busy {
		p.activityPoll.mu.Unlock()
		return
	}
	p.activityPoll.busy = true
	p.activityPoll.mu.Unlock()
	go func() {
		result, err := exchangeSupportRequest(supportRequest{Action: "activity"})
		state := workspaceActivity{}
		known := err == nil && result.OK && result.Activity != nil
		if known {
			state = *result.Activity
		}
		p.activityPoll.mu.Lock()
		p.activityPoll.pending, p.activityPoll.known, p.activityPoll.busy = state, known, false
		p.activityPoll.mu.Unlock()
		user32DLL.NewProc("PostMessageW").Call(p.window, 0x8002, 0, 0)
	}()
}
func (p *floatingWorkspace) applyActivity() {
	p.activityPoll.mu.Lock()
	state, known := p.activityPoll.pending, p.activityPoll.known
	p.activityPoll.mu.Unlock()
	changed := p.activity != state || p.activityKnown != known
	p.activity, p.activityKnown = state, known
	p.activityAt = time.Now()
	if changed {
		label := workspaceActivityLabel(known, state)
		// Include words, not just color, for assistive technologies.
		user32DLL.NewProc("SetWindowTextW").Call(p.dot, uintptr(unsafe.Pointer(uiString("Warden workspace — "+label+". Drag to move, click to open."))))
		p.render()
	}
}
