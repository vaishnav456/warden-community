package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrustDLL        = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = wintrustDLL.NewProc("WinVerifyTrust")
)

var wintrustActionGenericVerifyV2 = windows.GUID{
	Data1: 0x00aac56b,
	Data2: 0xcd44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
}

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               uintptr
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
}

const (
	wtdUINone                = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdStateActionVerify     = 1
	wtdStateActionClose      = 2
	wtdCacheOnlyURLRetrieval = 0x1000
)

// verifyAuthenticode asks Windows' native trust provider to validate the PE
// signature and its certificate chain. It intentionally avoids PowerShell so
// update trust does not depend on a script interpreter or localized output.
func verifyAuthenticode(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("invalid executable path: %w", err)
	}
	fileInfo := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: pathPtr,
	}
	data := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction:       wtdStateActionVerify,
		dwProvFlags:         wtdCacheOnlyURLRetrieval,
	}
	status, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)
	data.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)
	if int32(status) != 0 {
		return fmt.Errorf("WinVerifyTrust rejected the executable (status 0x%08x)", uint32(status))
	}
	return nil
}
