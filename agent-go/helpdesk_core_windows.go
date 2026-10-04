//go:build warden_core

package main

// Generic consent windows retain their existing behaviour. The optional
// ticket form implementation is excluded from Core at compile time.
type ticketFormUI struct {
	panel               uintptr
	total, page, offset int32
}

var currentTicketForm *ticketFormUI
var supportInputOptions []string
var supportInputSubmitLabel string

func startOptionalModules(stop <-chan struct{})      { go runModuleManager(stop) }
func (*ticketFormUI) changed(uintptr, uintptr) bool  { return false }
func (*ticketFormUI) submit() bool                   { return false }
func (*ticketFormUI) create(*wardenUI, uintptr) bool { return false }
func (*ticketFormUI) scrollTo(int32)                 {}
func runHelpdeskCreate(string) int                   { return launchHelpdeskModule("create") }
func runHelpdeskTickets() int                        { return launchHelpdeskModule("tickets") }
