package main

import (
	"sync"
	"unsafe"
)

type workspaceHelpdeskPoll struct {
	mu          sync.Mutex
	busy        bool
	pending     string
	known       bool
	initialized bool
	last        string
}

func (p *floatingWorkspace) pollHelpdesk() {
	p.helpdeskPoll.mu.Lock()
	if p.helpdeskPoll.busy {
		p.helpdeskPoll.mu.Unlock()
		return
	}
	p.helpdeskPoll.busy = true
	p.helpdeskPoll.mu.Unlock()
	go func() {
		result, err := exchangeSupportRequest(supportRequest{Action: "list"})
		known := err == nil && result.OK && result.Data != nil
		id := ""
		if known {
			id = result.Data.LatestReplyID
		}
		p.helpdeskPoll.mu.Lock()
		p.helpdeskPoll.pending, p.helpdeskPoll.known, p.helpdeskPoll.busy = id, known, false
		p.helpdeskPoll.mu.Unlock()
		user32DLL.NewProc("PostMessageW").Call(p.window, 0x8004, 0, 0)
	}()
}
func (p *floatingWorkspace) applyHelpdesk() {
	p.helpdeskPoll.mu.Lock()
	id, known := p.helpdeskPoll.pending, p.helpdeskPoll.known
	notify := known && p.helpdeskPoll.initialized && id != "" && id != p.helpdeskPoll.last
	if known {
		p.helpdeskPoll.last = id
		p.helpdeskPoll.initialized = true
	}
	p.helpdeskPoll.mu.Unlock()
	if !notify {
		return
	}
	data := workspaceNotifyIcon{Window: p.window, ID: 1, Flags: 16, InfoFlags: 1}
	data.Size = uint32(unsafe.Sizeof(data))
	copy(data.InfoTitle[:], uiUTF16("Warden Helpdesk"))
	copy(data.Info[:], uiUTF16("IT support updated a ticket. Open My requests to read it."))
	workspaceShell.NewProc("Shell_NotifyIconW").Call(1, uintptr(unsafe.Pointer(&data)))
}
