package main

// Native, dependency-free Warden UI. Helpers run in the user's session, never
// on the service's session-0 desktop. Closing an approval always denies access.
import (
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	uiRegisterClass    = user32DLL.NewProc("RegisterClassExW")
	uiCreateWindow     = user32DLL.NewProc("CreateWindowExW")
	uiDefWindow        = user32DLL.NewProc("DefWindowProcW")
	uiDestroyWindow    = user32DLL.NewProc("DestroyWindow")
	uiGetMessage       = user32DLL.NewProc("GetMessageW")
	uiTranslateMessage = user32DLL.NewProc("TranslateMessage")
	uiDispatchMessage  = user32DLL.NewProc("DispatchMessageW")
	uiDialogMessage    = user32DLL.NewProc("IsDialogMessageW")
	uiSendMessage      = user32DLL.NewProc("SendMessageW")
	uiShowWindow       = user32DLL.NewProc("ShowWindow")
	uiSetFocus         = user32DLL.NewProc("SetFocus")
	uiPostQuit         = user32DLL.NewProc("PostQuitMessage")
	uiSetTimer         = user32DLL.NewProc("SetTimer")
	uiWorkArea         = user32DLL.NewProc("SystemParametersInfoW")
	uiBeginPaint       = user32DLL.NewProc("BeginPaint")
	uiEndPaint         = user32DLL.NewProc("EndPaint")
	uiFillRect         = user32DLL.NewProc("FillRect")
	uiDrawText         = user32DLL.NewProc("DrawTextW")
	uiTextColor        = gdi32DLL.NewProc("SetTextColor")
	uiBackgroundMode   = gdi32DLL.NewProc("SetBkMode")
	uiCreateBrush      = gdi32DLL.NewProc("CreateSolidBrush")
	uiCreateFont       = gdi32DLL.NewProc("CreateFontW")
	uiCallback         = windows.NewCallback(wardenWindowProc)
	currentWardenUI    *wardenUI
)

type uiRect struct{ Left, Top, Right, Bottom int32 }
type uiClass struct {
	Size, Style                        uint32
	Callback                           uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Name                         *uint16
	SmallIcon                          uintptr
}
type uiMessage struct {
	Window  uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	X, Y    int32
	Private uint32
}
type uiPaint struct {
	DC              uintptr
	Erase           int32
	Rect            uiRect
	Restore, Update int32
	Reserved        [32]byte
}
type wardenUI struct {
	window, font, headingFont, smallFont, bodyBrush, deny, allow uintptr
	instruction, footer, severity, denyLabel, allowLabel         string
	approval, transient                                          bool
	deletion                                                     bool
	support                                                      bool
	edit                                                         uintptr
	choice                                                       uintptr
	scroll, editOriginal, scrollOriginal                         uintptr
	scrollDragging, scrollHover                                  bool
	scrollOffset                                                 int32
	scrollWheelRemainder                                         int32
	result                                                       int
	width, height                                                int32
	scale                                                        float64
	ticket                                                       *ticketFormUI
}

func uiString(s string) *uint16 {
	// Embedded NUL must not turn attacker-controlled content into a hidden suffix.
	p, _ := windows.UTF16PtrFromString(strings.ReplaceAll(s, "\x00", " "))
	return p
}
func (u *wardenUI) px(n int32) int32 { return int32(float64(n) * u.scale) }
func (u *wardenUI) fill(dc uintptr, r uiRect, color uintptr) {
	brush, _, _ := uiCreateBrush.Call(color)
	uiFillRect.Call(dc, uintptr(unsafe.Pointer(&r)), brush)
	procDeleteObject.Call(brush)
}
func (u *wardenUI) text(dc uintptr, text string, r uiRect, font, color uintptr) {
	old, _, _ := procSelectObject.Call(dc, font)
	uiTextColor.Call(dc, color)
	uiBackgroundMode.Call(dc, 1)
	uiDrawText.Call(dc, uintptr(unsafe.Pointer(uiString(text))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), 0x10|0x800) // word wrap, no mnemonic interpretation
	procSelectObject.Call(dc, old)
}

func wardenWindowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	u := currentWardenUI
	if u == nil {
		r, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
		return r
	}
	switch message {
	case 0x000f: // WM_PAINT
		var paint uiPaint
		dc, _, _ := uiBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		u.paint(dc)
		uiEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		return 0
	case 0x0111: // WM_COMMAND: only the affirmative button can approve.
		id := wParam & 0xffff
		if u.ticket != nil {
			if u.ticket.changed(lParam, wParam>>16) {
				return 0
			}
			if id == 6 && wParam>>16 == 0 && u.validAction(id, lParam) {
				if !u.ticket.submit() {
					return 0
				}
				u.result = 0
				uiDestroyWindow.Call(hwnd)
				return 0
			}
		}
		if lParam == u.edit && u.edit != 0 && wParam>>16 != 0 {
			u.refreshScroll()
			return 0
		}
		if wParam>>16 != 0 {
			break
		}
		if !u.validAction(id, lParam) {
			break
		}
		if id == 6 || id == 7 || id == 1 {
			if u.approval && id == 6 && lParam != 0 {
				if u.support {
					if u.choice != 0 {
						selected, _, _ := uiSendMessage.Call(u.choice, 0x0147, 0, 0)
						if int(selected) < 0 || int(selected) >= len(supportInputOptions) {
							return 0
						}
						supportMessageFromUI = supportInputOptions[int(selected)]
					} else {
						buffer := make([]uint16, 2001)
						user32DLL.NewProc("GetWindowTextW").Call(u.edit, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
						supportMessageFromUI = windows.UTF16ToString(buffer)
					}
				}
				u.result = 0
			}
			if u.deletion && id == 7 && lParam != 0 {
				u.result = 1
			}
			if !u.approval {
				u.result = 0
			}
			uiDestroyWindow.Call(hwnd)
			return 0
		}
	case 0x002b:
		if lParam != 0 {
			item := (*workspaceDrawItem)(unsafe.Pointer(lParam))
			if item.ControlID == 21 {
				u.paintScroll(item)
			} else {
				u.paintButton(item)
			}
			return 1
		}
	case 0x020a:
		if u.edit != 0 {
			uiSendMessage.Call(u.edit, uintptr(message), wParam, lParam)
			return 0
		}
	case 0x0133, 0x0134, 0x0138: // native editable/read-only text surface, not HTML.
		if u.ticket != nil || lParam == u.edit || lParam == u.choice || (u.choice != 0 && message == 0x0134) {
			uiTextColor.Call(wParam, 0x00f2efde)
			gdi32DLL.NewProc("SetBkColor").Call(wParam, 0x0042351e)
			return u.bodyBrush
		}
	case 0x0084: // Drag the quiet top bar; the window has no fake title controls.
		var cursor workspacePoint
		user32DLL.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&cursor)))
		user32DLL.NewProc("ScreenToClient").Call(hwnd, uintptr(unsafe.Pointer(&cursor)))
		if cursor.Y >= 0 && cursor.Y < u.px(70) {
			return 2
		}
	case 0x0010, 0x0113: // WM_CLOSE / WM_TIMER: deny, including expiry.
		uiDestroyWindow.Call(hwnd)
		return 0
	case 0x0002: // WM_DESTROY
		uiPostQuit.Call(0)
		return 0
	case 0x0021: // WM_MOUSEACTIVATE: notifications never steal keyboard focus.
		if u.transient {
			return 3
		} // MA_NOACTIVATE
	}
	r, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func runWardenUserDialog(title, instruction, content, footer, severity string, approval bool) int {
	return runWardenWindow(title, instruction, content, footer, severity, approval, false)
}

func runWardenWindow(title, instruction, content, footer, severity string, approval, transient bool) int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procSetProcessDPIAware.Call()
	graphicsToken, graphicsErr := workspaceStartGraphics()
	if graphicsErr != nil || graphicsToken == 0 {
		return 2
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(graphicsToken)
	u := &wardenUI{instruction: instruction, footer: footer, severity: severity, approval: approval, transient: transient, result: 2, scale: 1}
	u.deletion = title == "Warden Home deletions" && approval
	u.support = title == "Warden Support" && approval
	if u.support {
		u.ticket = currentTicketForm
	}
	if p := user32DLL.NewProc("GetDpiForSystem"); p.Find() == nil {
		dpi, _, _ := p.Call()
		if dpi >= 96 {
			u.scale = float64(dpi) / 96
		}
	}
	var work uiRect
	if ok, _, _ := uiWorkArea.Call(0x30, 0, uintptr(unsafe.Pointer(&work)), 0); ok == 0 {
		return 2
	}
	// Fit even a small desktop; long content stays accessible in a scrollable edit.
	u.width, u.height = u.px(600), u.px(550)
	if u.ticket != nil {
		u.height = u.px(740)
	}
	if transient {
		u.width, u.height = u.px(430), u.px(360)
	}
	if u.width > work.Right-work.Left-u.px(24) {
		u.width = work.Right - work.Left - u.px(24)
	}
	if u.height > work.Bottom-work.Top-u.px(24) {
		u.height = work.Bottom - work.Top - u.px(24)
	}
	if u.width < u.px(280) || u.height < u.px(300) {
		return 2
	}
	if u.support && len(supportInputOptions) > 0 && u.height < u.px(360) {
		return 2
	}
	x, y := work.Left+(work.Right-work.Left-u.width)/2, work.Top+(work.Bottom-work.Top-u.height)/2
	if transient {
		x, y = work.Right-u.width-u.px(12), work.Bottom-u.height-u.px(12)
	}
	instance, _, _ := kernel32DLL.NewProc("GetModuleHandleW").Call(0)
	className := uiString("WardenWorkspaceWindow")
	class := uiClass{Callback: uiCallback, Instance: instance, Name: className}
	class.Cursor, _, _ = user32DLL.NewProc("LoadCursorW").Call(0, 32512)
	class.Size = uint32(unsafe.Sizeof(class))
	if atom, _, _ := uiRegisterClass.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		return 2
	}
	defer user32DLL.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(className)), instance)
	u.font, _, _ = uiCreateFont.Call(uintptr(-int64(u.px(16))), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	u.headingFont, _, _ = uiCreateFont.Call(uintptr(-int64(u.px(20))), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(u.font)
	defer procDeleteObject.Call(u.headingFont)
	u.smallFont, _, _ = uiCreateFont.Call(uintptr(-int64(u.px(13))), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(u.smallFont)
	u.bodyBrush, _, _ = uiCreateBrush.Call(0x0042351e)
	defer procDeleteObject.Call(u.bodyBrush)
	currentWardenUI = u
	defer func() { currentWardenUI = nil }()
	extended := uintptr(0x00010008) // control parent, topmost
	if transient {
		extended |= 0x08000080
	} // NOACTIVATE, TOOLWINDOW
	u.window, _, _ = uiCreateWindow.Call(extended, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(uiString(title))), 0x80000000|0x00800000,
		uintptr(x), uintptr(y), uintptr(u.width), uintptr(u.height), 0, 0, instance, 0)
	if u.window == 0 {
		return 2
	}
	// DWM rounds the native frame on supported Windows; unsupported systems
	// retain the same fully functional controls, with no dependency download.
	if dwm := windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute"); dwm.Find() == nil {
		corner, dark := uint32(2), uint32(1)
		dwm.Call(u.window, 33, uintptr(unsafe.Pointer(&corner)), 4)
		dwm.Call(u.window, 20, uintptr(unsafe.Pointer(&dark)), 4)
	}
	child := func(class, text string, style uintptr, x, y, w, h int32, id uintptr) uintptr {
		hwnd, _, _ := uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString(class))), uintptr(unsafe.Pointer(uiString(text))), 0x50000000|style,
			uintptr(x), uintptr(y), uintptr(w), uintptr(h), u.window, id, instance, 0)
		uiSendMessage.Call(hwnd, 0x30, u.font, 1) // WM_SETFONT
		return hwnd
	}
	edit := uintptr(1)
	if u.ticket != nil {
		if !u.ticket.create(u, instance) {
			uiDestroyWindow.Call(u.window)
			return 2
		}
	} else {
		body := content
		if severity == "critical" {
			body = "IMPORTANT\r\n\r\n" + body
		}
		body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
		editStyle := uintptr(0x0004 | 0x0040 | 0x0800 | 0x00010000)
		if u.support {
			editStyle &^= 0x0800
			editStyle |= 0x1000 // ES_WANTRETURN: multiline helpdesk descriptions
			if len(supportInputOptions) > 0 {
				editStyle |= 0x0800
			}
		}
		editHeight := u.height - u.px(280)
		if u.support && len(supportInputOptions) > 0 {
			editHeight -= u.px(60)
		}
		edit = child("EDIT", body, editStyle, u.px(36), u.px(152), u.width-u.px(84), editHeight, 20)
		u.edit = edit
		if edit == 0 {
			uiDestroyWindow.Call(u.window)
			return 2
		}
		u.editOriginal, _, _ = user32DLL.NewProc("SetWindowLongPtrW").Call(edit, ^uintptr(3), uiEditCallback)
		u.scroll = child("BUTTON", "Scroll message. Use arrow keys, Page Up, Page Down, Home or End.", 0x1000b,
			u.width-u.px(42), u.px(152), u.px(14), editHeight, 21)
		if u.scroll == 0 || u.editOriginal == 0 {
			uiDestroyWindow.Call(u.window)
			return 2
		}
		u.scrollOriginal, _, _ = user32DLL.NewProc("SetWindowLongPtrW").Call(u.scroll, ^uintptr(3), uiScrollCallback)
		if u.scrollOriginal == 0 {
			uiDestroyWindow.Call(u.window)
			return 2
		}
		u.refreshScroll()
		if u.support && len(supportInputOptions) > 0 {
			u.choice = child("COMBOBOX", "", 0x00010003|0x00200000, u.px(36), u.height-u.px(165), u.width-u.px(72), u.px(180), 22)
			if u.choice == 0 {
				uiDestroyWindow.Call(u.window)
				return 2
			}
			for _, option := range supportInputOptions {
				uiSendMessage.Call(u.choice, 0x0143, 0, uintptr(unsafe.Pointer(uiString(option))))
			}
			uiSendMessage.Call(u.choice, 0x014e, 0, 0)
		}
		if u.support {
			uiSendMessage.Call(edit, 0x00c5, 2000, 0)
		}
	}
	label, buttonID := "Dismiss", uintptr(1)
	if approval {
		label, buttonID = "Deny access", 7
	}
	if u.deletion {
		label = "Restore files"
	}
	if u.support {
		label = "Cancel"
	}
	buttonWidth := u.px(150)
	if approval {
		buttonWidth = (u.width - u.px(72)) / 2
	}
	deny := child("BUTTON", label, 0x0001000b, u.width-u.px(24)-buttonWidth, u.height-u.px(57), buttonWidth, u.px(38), buttonID)
	allow := uintptr(1)
	if approval {
		allowLabel := "Allow this session"
		if u.support {
			allowLabel = "Send request"
			if u.ticket != nil {
				allowLabel = "Send ticket"
			}
			if supportInputSubmitLabel != "" {
				allowLabel = supportInputSubmitLabel
			}
		}
		if u.deletion {
			allowLabel = "Delete from Home"
		}
		u.allowLabel = allowLabel
		allow = child("BUTTON", allowLabel, 0x0001000b, u.px(24), u.height-u.px(57), buttonWidth, u.px(38), 6)
	}
	u.deny, u.denyLabel = deny, label
	if approval {
		u.allow = allow
	}
	if edit == 0 || deny == 0 || allow == 0 {
		uiDestroyWindow.Call(u.window)
		return 2
	}
	uiSendMessage.Call(u.window, 0x401, buttonID, 0) // DM_SETDEFID: Enter defaults to deny.
	show := uintptr(5)
	if transient {
		show = 4
		uiSetTimer.Call(u.window, 1, 15000, 0)
	}
	if approval && !u.support {
		uiSetTimer.Call(u.window, 1, 55000, 0)
	}
	// Cross-session helpers are started with STARTF_USESHOWWINDOW/SW_HIDE.
	// Consume that startup override before explicitly showing our own window.
	uiShowWindow.Call(u.window, 0)
	uiShowWindow.Call(u.window, show)
	if !transient {
		uiSetFocus.Call(deny)
	}
	var msg uiMessage
	for {
		r, _, _ := uiGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if msg.Message == 0x100 && msg.WParam == 27 {
			uiDestroyWindow.Call(u.window)
			continue
		}
		if !transient && msg.Message == 0x100 && msg.WParam == 13 {
			if u.ticket != nil && msg.Window != u.allow && msg.Window != u.deny {
				// Enter edits multiline text; only the focused Send button submits.
				uiTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
				uiDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
				continue
			}
			// Never turn typing Enter into consent. Only the deliberately
			// focused affirmative button can receive its own activation.
			if u.support && msg.Window == u.edit {
				uiTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
				uiDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
				continue
			}
			id, source := buttonID, u.deny
			if approval && msg.Window == u.allow {
				id, source = 6, u.allow
			}
			uiSendMessage.Call(u.window, 0x111, id, source)
			continue
		}
		if !transient {
			if handled, _, _ := uiDialogMessage.Call(u.window, uintptr(unsafe.Pointer(&msg))); handled != 0 {
				continue
			}
		}
		uiTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		uiDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return u.result
}
