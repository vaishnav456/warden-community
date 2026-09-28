//go:build windows

package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Passwords must not be passed to net.exe: child-process command lines are
// observable by administrators and commonly collected by EDR tooling.  The
// Windows NetAPI accepts the secret through process memory instead.
var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = netapi32.NewProc("NetUserAdd")
	procNetUserSetInfo          = netapi32.NewProc("NetUserSetInfo")
	procNetUserDel              = netapi32.NewProc("NetUserDel")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
)

const (
	userPrivUser       = 1
	ufScript           = 0x0001
	ufPasswdCantChange = 0x0040
	ufNormalAccount    = 0x0200
	ufPasswordExpired  = 0x800000
)

type userInfo1 struct {
	name        *uint16
	password    *uint16
	passwordAge uint32
	privilege   uint32
	homeDir     *uint16
	comment     *uint16
	flags       uint32
	scriptPath  *uint16
}

type userInfo1003 struct {
	password *uint16
}

type userInfo1011 struct {
	fullName *uint16
}

type localGroupMembersInfo3 struct {
	domainAndName *uint16
}

func netStatusError(operation string, status uintptr) error {
	if status == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, syscall.Errno(status))
}

func createLocalUserSecure(username, password, fullName string, mustChange bool) error {
	namePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	passwordPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	flags := uint32(ufScript | ufNormalAccount)
	if mustChange {
		flags |= ufPasswordExpired
	} else {
		flags |= ufPasswdCantChange
	}
	info := userInfo1{name: namePtr, password: passwordPtr, privilege: userPrivUser, flags: flags}
	status, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), 0)
	runtime.KeepAlive(passwordPtr)
	if err := netStatusError("NetUserAdd", status); err != nil {
		return err
	}
	if fullName != "" {
		if err := setLocalUserFullNameSecure(username, fullName); err != nil {
			_, _, _ = procNetUserDel.Call(0, uintptr(unsafe.Pointer(namePtr)))
			return err
		}
	}
	return nil
}

func setLocalUserFullNameSecure(username, fullName string) error {
	namePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	fullNamePtr, err := windows.UTF16PtrFromString(fullName)
	if err != nil {
		return err
	}
	info := userInfo1011{fullName: fullNamePtr}
	status, _, _ := procNetUserSetInfo.Call(
		0, uintptr(unsafe.Pointer(namePtr)), 1011,
		uintptr(unsafe.Pointer(&info)), 0,
	)
	return netStatusError("NetUserSetInfo(full name)", status)
}

func setLocalUserPasswordSecure(username, password string) error {
	namePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	passwordPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	info := userInfo1003{password: passwordPtr}
	status, _, _ := procNetUserSetInfo.Call(
		0, uintptr(unsafe.Pointer(namePtr)), 1003,
		uintptr(unsafe.Pointer(&info)), 0,
	)
	runtime.KeepAlive(passwordPtr)
	return netStatusError("NetUserSetInfo(password)", status)
}

// ensureLocalGroupMemberSecure is idempotent and does not invoke net.exe.
// ERROR_MEMBER_IN_ALIAS (1378) means the requested state already exists.
func ensureLocalGroupMemberSecure(group, username string) error {
	groupPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return err
	}
	namePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	info := localGroupMembersInfo3{domainAndName: namePtr}
	status, _, _ := procNetLocalGroupAddMembers.Call(
		0, uintptr(unsafe.Pointer(groupPtr)), 3,
		uintptr(unsafe.Pointer(&info)), 1,
	)
	if status == 1378 {
		return nil
	}
	return netStatusError("NetLocalGroupAddMembers", status)
}
