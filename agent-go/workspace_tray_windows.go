package main

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var workspaceShell = windows.NewLazySystemDLL("shell32.dll")
var workspaceTrayCallback = windows.NewCallback(workspaceTrayProc)

type workspaceNotifyIcon struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Version             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                [16]byte
	BalloonIcon         uintptr
}
type workspaceIconInfo struct {
	IsIcon      int32
	X, Y        uint32
	Mask, Color uintptr
}

func workspaceTrayIcon(known bool, activity workspaceActivity) uintptr {
	s := workspaceNewSurface(32, 32)
	if s == nil {
		return 0
	}
	defer s.close()
	top, bottom := uint32(0xff1688ff), uint32(0xff6267ef)
	switch workspaceActivityLabel(known, activity) {
	case "STATUS UNKNOWN":
		top, bottom = 0xff9d7b42, 0xff625036
	case "REMOTE ACTIVE":
		top, bottom = 0xff278ef5, 0xff225ba7
	case "RECORDING":
		top, bottom = 0xffe04b58, 0xff9d2638
	}
	s.gradientCircle(1, 1, 30, top, bottom)
	s.wardenMark(3, 3, 26, 0xffffffff)
	workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
	// CreateIconIndirect copies these bitmaps; the resulting icon owns its data.
	maskBits := make([]byte, 128)
	mask, _, _ := gdi32DLL.NewProc("CreateBitmap").Call(32, 32, 1, 1, uintptr(unsafe.Pointer(&maskBits[0])))
	if mask == 0 {
		return 0
	}
	defer procDeleteObject.Call(mask)
	info := workspaceIconInfo{IsIcon: 1, Mask: mask, Color: s.bitmap}
	icon, _, _ := user32DLL.NewProc("CreateIconIndirect").Call(uintptr(unsafe.Pointer(&info)))
	return icon
}

func (p *floatingWorkspace) updateTray(force bool) bool {
	label := workspaceActivityLabel(p.activityKnown, p.activity)
	if !force && p.trayIcon != 0 && p.trayLabel == label {
		return true
	}
	icon := workspaceTrayIcon(p.activityKnown, p.activity)
	if icon == 0 {
		return false
	}
	data := workspaceNotifyIcon{Window: p.window, ID: 1, Flags: 1 | 2 | 4 | 0x80, Callback: 0x8003, Icon: icon}
	data.Size = uint32(unsafe.Sizeof(data))
	copy(data.Tip[:], uiUTF16("Warden — "+label+". Click for Helpdesk."))
	operation := uintptr(1) // NIM_MODIFY, add if missing (including Explorer restart).
	if p.trayIcon == 0 {
		operation = 0
	}
	ok, _, _ := workspaceShell.NewProc("Shell_NotifyIconW").Call(operation, uintptr(unsafe.Pointer(&data)))
	if ok == 0 && operation == 1 {
		ok, _, _ = workspaceShell.NewProc("Shell_NotifyIconW").Call(0, uintptr(unsafe.Pointer(&data)))
	}
	if ok == 0 {
		user32DLL.NewProc("DestroyIcon").Call(icon)
		return false
	}
	data.Version = 4
	workspaceShell.NewProc("Shell_NotifyIconW").Call(4, uintptr(unsafe.Pointer(&data)))
	if p.trayIcon != 0 {
		user32DLL.NewProc("DestroyIcon").Call(p.trayIcon)
	}
	p.trayIcon, p.trayLabel = icon, label
	return true
}
func uiUTF16(value string) []uint16 { result, _ := windows.UTF16FromString(value); return result }

func (p *floatingWorkspace) trayMenu() {
	menu, _, _ := user32DLL.NewProc("CreatePopupMenu").Call()
	if menu == 0 {
		return
	}
	defer user32DLL.NewProc("DestroyMenu").Call(menu)
	appendItem := func(flags, id uintptr, label string) {
		user32DLL.NewProc("AppendMenuW").Call(menu, flags, id, uintptr(unsafe.Pointer(uiString(label))))
	}
	appendItem(1|2, 0, "Warden — "+workspaceActivityLabel(p.activityKnown, p.activity))
	appendItem(0x800, 0, "")
	appendItem(0, 102, "Contact Helpdesk")
	appendItem(0, 101, "My requests")
	// No Quit/Remove command. The normal-user helper cannot stop the agent.
	var cursor workspacePoint
	user32DLL.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&cursor)))
	user32DLL.NewProc("SetForegroundWindow").Call(p.window)
	command, _, _ := user32DLL.NewProc("TrackPopupMenu").Call(menu, 0x100|0x2, uintptr(cursor.X), uintptr(cursor.Y), 0, p.window, 0)
	user32DLL.NewProc("PostMessageW").Call(p.window, 0, 0, 0)
	if command == 102 {
		workspaceLaunch("--request-support")
	}
	if command == 101 {
		workspaceLaunch("--support-status")
	}
}
func workspaceTrayProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	p := workspacePanel
	if p != nil {
		if p.taskbarCreated != 0 && message == p.taskbarCreated {
			p.updateTray(true)
			return 0
		}
		switch message {
		case 0x8003:
			switch lParam & 0xffff {
			case 0x0400, 0x0401, 0x007b: // NIN_SELECT, NIN_KEYSELECT, WM_CONTEXTMENU
				p.trayMenu()
			case 0x0405:
				workspaceLaunch("--support-status")
			}
			return 0
		case 0x8002:
			p.applyActivity()
			return 0
		case 0x8004:
			p.applyHelpdesk()
			return 0
		case 0x0113:
			if wParam == 8 {
				if p.activityKnown && time.Since(p.activityAt) > 10*time.Second {
					p.activityKnown = false
					p.updateTray(false)
				}
				p.pollActivity()
			}
			if wParam == 9 {
				p.updateTray(true)
			}
			if wParam == 10 {
				p.pollHelpdesk()
			}
			return 0
		case 0x0010:
			return 0 // no user-facing exit command
		case 0x0002:
			uiPostQuit.Call(0)
			return 0
		}
	}
	result, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

// The tray owns only a hidden message window, never a desktop overlay.
// Normal-user token, single per-session instance, existing service supervision.
func runFloatingWorkspace() int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return 1
	}
	user, err := token.GetTokenUser()
	token.Close()
	if err != nil || user.User.Sid.String() == "S-1-5-18" {
		return 1
	}
	mutex, err := windows.CreateMutex(nil, false, uiString("Local\\WardenWorkspace.v1"))
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if err != nil {
		return 0
	}
	graphics, err := workspaceStartGraphics()
	if err != nil || graphics == 0 {
		return 1
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(graphics)
	instance, _, _ := kernel32DLL.NewProc("GetModuleHandleW").Call(0)
	name := uiString("WardenWorkspaceTray")
	class := uiClass{Size: uint32(unsafe.Sizeof(uiClass{})), Callback: workspaceTrayCallback, Instance: instance, Name: name}
	if atom, _, _ := uiRegisterClass.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		return 1
	}
	defer user32DLL.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(name)), instance)
	p := &floatingWorkspace{trayMode: true}
	workspacePanel = p
	defer func() { workspacePanel = nil }()
	p.window, _, _ = uiCreateWindow.Call(0x80, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(uiString("Warden"))), 0x80000000, 0, 0, 0, 0, 0, 0, instance, 0)
	if p.window == 0 {
		return 1
	}
	defer uiDestroyWindow.Call(p.window)
	registered, _, _ := user32DLL.NewProc("RegisterWindowMessageW").Call(uintptr(unsafe.Pointer(uiString("TaskbarCreated"))))
	p.taskbarCreated = uint32(registered)
	if !p.updateTray(true) {
		return 1
	}
	defer func() {
		data := workspaceNotifyIcon{Window: p.window, ID: 1}
		data.Size = uint32(unsafe.Sizeof(data))
		workspaceShell.NewProc("Shell_NotifyIconW").Call(2, uintptr(unsafe.Pointer(&data)))
		if p.trayIcon != 0 {
			user32DLL.NewProc("DestroyIcon").Call(p.trayIcon)
		}
	}()
	p.pollActivity()
	p.pollHelpdesk()
	uiSetTimer.Call(p.window, 8, 3000, 0)
	uiSetTimer.Call(p.window, 9, 30000, 0)
	uiSetTimer.Call(p.window, 10, 60000, 0)
	var message uiMessage
	for {
		result, _, _ := uiGetMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) <= 0 {
			break
		}
		uiTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		uiDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
	}
	return 0
}
