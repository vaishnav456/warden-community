package main

import (
 "os"
 "golang.org/x/sys/windows"
)

// This application is a normal-user pipe client. It has no enrollment token,
// API key, device signing key, updater, service entry point or remote control.
func main() {
 token := windows.GetCurrentProcessToken()
 user, err := token.GetTokenUser()
 if err != nil || user.User.Sid.String() == "S-1-5-18" { os.Exit(3) }
 if len(os.Args) != 2 { os.Exit(2) }
 switch os.Args[1] {
 case "create": os.Exit(runHelpdeskCreate(""))
 case "tickets": os.Exit(runHelpdeskTickets())
 default: os.Exit(2)
 }
}
