//go:build windows

package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	topologyWTSAPI32               = windows.NewLazySystemDLL("wtsapi32.dll")
	topologyWTSEnumerateSessionsW  = topologyWTSAPI32.NewProc("WTSEnumerateSessionsW")
	topologyWTSQuerySessionInfoW   = topologyWTSAPI32.NewProc("WTSQuerySessionInformationW")
	topologyWTSFreeMemory          = topologyWTSAPI32.NewProc("WTSFreeMemory")
	topologyActiveConsoleSessionID = windows.NewLazySystemDLL("kernel32.dll").NewProc("WTSGetActiveConsoleSessionId")
)

const (
	wtsActive             = 0
	topologyWTSUserName   = 5
	topologyWTSDomainName = 7
)

type wtsSessionInfo struct {
	sessionID      uint32
	winStationName *uint16
	state          uint32
}

func queryWTSSessionText(sessionID uint32, infoClass uintptr) string {
	var value *uint16
	var bytes uint32
	ok, _, _ := topologyWTSQuerySessionInfoW.Call(
		0, uintptr(sessionID), infoClass,
		uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&bytes)),
	)
	if ok == 0 || value == nil {
		return ""
	}
	defer topologyWTSFreeMemory.Call(uintptr(unsafe.Pointer(value)))
	return strings.TrimSpace(windows.UTF16PtrToString(value))
}

// currentInteractiveUser returns the active console/RDP identity instead of
// the service account (SYSTEM) running Warden. Empty means no active session.
func currentInteractiveUser() string {
	var buffer *wtsSessionInfo
	var count uint32
	ok, _, _ := topologyWTSEnumerateSessionsW.Call(
		0, 0, 1, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&count)),
	)
	var sessionID uint32 = 0xffffffff
	if ok != 0 && buffer != nil && count > 0 {
		defer topologyWTSFreeMemory.Call(uintptr(unsafe.Pointer(buffer)))
		for _, session := range unsafe.Slice(buffer, int(count)) {
			if session.state == wtsActive {
				sessionID = session.sessionID
				break
			}
		}
	}
	if sessionID == 0xffffffff {
		value, _, _ := topologyActiveConsoleSessionID.Call()
		sessionID = uint32(value)
	}
	if sessionID == 0xffffffff {
		return ""
	}
	username := queryWTSSessionText(sessionID, topologyWTSUserName)
	if username == "" {
		return ""
	}
	domain := queryWTSSessionText(sessionID, topologyWTSDomainName)
	if domain != "" && !strings.EqualFold(domain, ".") {
		return domain + `\` + username
	}
	return username
}
