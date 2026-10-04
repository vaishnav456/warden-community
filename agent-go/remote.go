package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ── Windows API declarations ──────────────────────────────────────────────────

var (
	user32DLL   = windows.NewLazySystemDLL("user32.dll")
	gdi32DLL    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32DLL = windows.NewLazySystemDLL("kernel32.dll")

	// golang.org/x/sys/windows does not wrap the GlobalAlloc/GlobalLock
	// family (they predate HeapAlloc and are rarely needed) — declared
	// directly, matching this file's existing pattern for GDI/User32 calls.
	procGlobalAlloc  = kernel32DLL.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32DLL.NewProc("GlobalLock")
	procGlobalUnlock = kernel32DLL.NewProc("GlobalUnlock")
	procGlobalFree   = kernel32DLL.NewProc("GlobalFree")

	procGetDC                  = user32DLL.NewProc("GetDC")
	procGetForegroundWindow    = user32DLL.NewProc("GetForegroundWindow")
	procReleaseDC              = user32DLL.NewProc("ReleaseDC")
	procGetSystemMetrics       = user32DLL.NewProc("GetSystemMetrics")
	procSendInput              = user32DLL.NewProc("SendInput")
	procOpenClipboard          = user32DLL.NewProc("OpenClipboard")
	procCloseClipboard         = user32DLL.NewProc("CloseClipboard")
	procEmptyClipboard         = user32DLL.NewProc("EmptyClipboard")
	procGetClipboardData       = user32DLL.NewProc("GetClipboardData")
	procSetClipboardData       = user32DLL.NewProc("SetClipboardData")
	procSetProcessDPIAware     = user32DLL.NewProc("SetProcessDPIAware")
	procSetCursorPos           = user32DLL.NewProc("SetCursorPos")
	procEnumDisplayMonitors    = user32DLL.NewProc("EnumDisplayMonitors")
	procGetThreadDesktop       = user32DLL.NewProc("GetThreadDesktop")
	procOpenInputDesktop       = user32DLL.NewProc("OpenInputDesktop")
	procCloseDesktop           = user32DLL.NewProc("CloseDesktop")
	procGetUserObjectInfo      = user32DLL.NewProc("GetUserObjectInformationW")
	procCreateCompatibleDC     = gdi32DLL.NewProc("CreateCompatibleDC")
	procDeleteDC               = gdi32DLL.NewProc("DeleteDC")
	procCreateCompatibleBitmap = gdi32DLL.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32DLL.NewProc("SelectObject")
	procDeleteObject           = gdi32DLL.NewProc("DeleteObject")
	procBitBlt                 = gdi32DLL.NewProc("BitBlt")
	procGetDIBits              = gdi32DLL.NewProc("GetDIBits")
	procGdiFlush               = gdi32DLL.NewProc("GdiFlush")
)


// sendSecureAttentionSequence runs in the Warden LocalSystem service, which
// is the security boundary Windows permits to generate a software SAS. A
// Ctrl+Alt+Delete assembled from SendInput events is intentionally ignored by
// Winlogon and therefore cannot unlock the secure attention screen.
func sendSecureAttentionSequence() error {
	const policyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open software SAS policy: %w", err)
	}
	value, _, readErr := key.GetIntegerValue("SoftwareSASGeneration")
	if readErr != nil && readErr != registry.ErrNotExist {
		key.Close()
		return fmt.Errorf("read software SAS policy: %w", readErr)
	}
	// Values 1 and 3 permit services. Preserve an administrator's existing
	// accessibility-app permission (bit 2) instead of replacing the policy.
	if value&1 == 0 {
		if err := key.SetDWordValue("SoftwareSASGeneration", uint32(value|1)); err != nil {
			key.Close()
			return fmt.Errorf("enable software SAS for services: %w", err)
		}
	}
	key.Close()

	sasDLL := windows.NewLazySystemDLL("sas.dll")
	if err := sasDLL.Load(); err != nil {
		return fmt.Errorf("load sas.dll: %w", err)
	}
	procSendSAS := sasDLL.NewProc("SendSAS")
	if err := procSendSAS.Find(); err != nil {
		return fmt.Errorf("resolve SendSAS: %w", err)
	}
	procSendSAS.Call(0) // FALSE: service context, not an impersonated user.
	return nil
}

func runRemoteConsentPrompt(helperName, reason, warningTitle, warningMessage string, requestedAccess []string) int {
	if len(helperName) > 160 {
		helperName = helperName[:160]
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	if len(warningTitle) > 120 {
		warningTitle = warningTitle[:120]
	}
	if len(warningMessage) > 500 {
		warningMessage = warningMessage[:500]
	}
	if warningTitle == "" {
		warningTitle = "Warden remote support"
	}
	if warningMessage == "" {
		warningMessage = "Your support technician can see this screen and may control this computer."
	}
	accessText := "View screen"
	if len(requestedAccess) > 0 {
		accessText = strings.Join(requestedAccess, "\n• ")
	}
	return runWardenUserDialog(
		warningTitle,
		fmt.Sprintf("%s is requesting access", helperName),
		fmt.Sprintf("%s\n\nReason\n%s\n\nRequested access\n• %s", warningMessage, reason, accessText),
		"Allow only someone you trust. Deny, close or wait to keep this computer private. This request expires in 55 seconds.",
		"warning", true,
	)
}

func requestRemoteConsent(sessionID, helperName, reason, warningTitle, warningMessage string, requestedAccess []string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	accessJSON, _ := json.Marshal(requestedAccess)
	helper, err := launchInteractiveHelper(exePath, []string{
		"--remote-consent", helperName, reason, warningTitle, warningMessage, string(accessJSON),
	})
	if err != nil {
		reportRemoteConsent(sessionID, "denied")
		return fmt.Errorf("could not display consent prompt: %w", err)
	}
	code, finished := helper.wait(60 * time.Second)
	if !finished {
		helper.terminate(2 * time.Second)
		reportRemoteConsent(sessionID, "expired")
		return fmt.Errorf("remote consent prompt expired")
	}
	if code != 0 {
		reportRemoteConsent(sessionID, "denied")
		return fmt.Errorf("remote user denied access")
	}
	reportRemoteConsent(sessionID, "approved")
	return nil
}

const (
	smCxScreen = 0
	smCyScreen = 1
	srccopy    = 0x00CC0020
	captureBlt = 0x40000000 // include DWM/layered windows in the captured frame
	cfUnicode  = 13

	mouseMoveAbsolute = 0x0001 | 0x8000
	mouseLeftDown     = 0x0002
	mouseLeftUp       = 0x0004
	mouseRightDown    = 0x0008
	mouseRightUp      = 0x0010
	mouseMidDown      = 0x0020
	mouseMidUp        = 0x0040
	mouseWheel        = 0x0800
	mouseAbsolute     = 0x8000
	wheelDelta        = 120
	keyUp             = 0x0002
	keyUnicode        = 0x0004

	gmemMoveable       = 0x0002
	uoiName            = 2      // UOI_NAME, for GetUserObjectInformationW
	desktopReadObjects = 0x0001 // DESKTOP_READOBJECTS
)

func desktopObjectName(handle uintptr) (string, error) {
	buf := make([]uint16, 256)
	var needed uint32
	ok, _, callErr := procGetUserObjectInfo.Call(
		handle, uoiName,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&needed)),
	)
	if ok == 0 {
		return "", fmt.Errorf("GetUserObjectInformationW: %w", callErr)
	}
	return windows.UTF16ToString(buf), nil
}

// currentDesktopName returns the name of the desktop the calling thread is
// currently associated with (e.g. "Default" or "Winlogon"). Used to decide
// whether DXGI Desktop Duplication is even worth attempting: Microsoft
// documents it as not working on the secure desktop, and this was confirmed
// live — it can report itself as "active" there while actually only ever
// producing black frames, unlike the GDI BitBlt path (fixed separately),
// which does work there.
func currentDesktopName() (string, error) {
	hDesktop, _, _ := procGetThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	if hDesktop == 0 {
		return "", fmt.Errorf("GetThreadDesktop failed")
	}
	return desktopObjectName(hDesktop)
}

// inputDesktopName returns the desktop that currently owns keyboard/mouse
// input in this helper's interactive window station. Ctrl+Alt+Delete changes
// the input desktop to Winlogon without emitting a WTS lock notification.
func inputDesktopName() (string, error) {
	hDesktop, _, callErr := procOpenInputDesktop.Call(0, 0, desktopReadObjects)
	if hDesktop == 0 {
		return "", fmt.Errorf("OpenInputDesktop: %w", callErr)
	}
	defer procCloseDesktop.Call(hDesktop)
	return desktopObjectName(hDesktop)
}

func desktopNamesDiffer(current, input string) bool {
	return current != "" && input != "" && !strings.EqualFold(current, input)
}

func requestEndpointChatReply(message string) (string, error) {
	if len(message) > 2000 {
		message = message[:2000]
	}
	token := randomSessionToken()
	pipeName := `\\.\pipe\WardenChat-` + token
	sddl := "D:(A;;GA;;;SY)"
	if userSID, err := activeConsoleUserStringSID(); err == nil {
		sddl = fmt.Sprintf("D:(A;;GA;;;SY)(A;;GW;;;%s)", userSID)
	}
	pipe, err := createPipeServer(pipeName, windows.PIPE_ACCESS_INBOUND, sddl)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(pipe)
	encoded := base64.StdEncoding.EncodeToString([]byte(message))
	script := `$m=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($args[1]));` +
		`Add-Type -AssemblyName Microsoft.VisualBasic;` +
		`$r=[Microsoft.VisualBasic.Interaction]::InputBox($m,'Warden Support — reply','');` +
		`$p=New-Object IO.Pipes.NamedPipeClientStream('.',$args[0],[IO.Pipes.PipeDirection]::Out);` +
		`$p.Connect(5000);$w=New-Object IO.StreamWriter($p);$w.Write($r);$w.Dispose();$p.Dispose()`
	helper, err := launchInteractiveHelper("powershell.exe", []string{
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
		script, token, encoded,
	})
	if err != nil {
		return "", err
	}
	defer helper.terminate(2 * time.Second)
	connectDone := make(chan error, 1)
	go func() { connectDone <- connectNamedPipeTolerant(pipe) }()
	select {
	case err := <-connectDone:
		if err != nil {
			return "", err
		}
	case <-time.After(2 * time.Minute):
		helper.terminate(2 * time.Second)
		_ = windows.CancelIoEx(pipe, nil)
		return "", fmt.Errorf("endpoint chat reply timed out")
	}
	data, err := io.ReadAll(io.LimitReader(pipeFile{pipe}, 4000))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// INPUT structures for SendInput — sized for 64-bit Windows (INPUT = 40 bytes)
// Layout: DWORD type (4) + padding (4) + union (32)
// MOUSEINPUT: dx(4)+dy(4)+mouseData(4)+dwFlags(4)+time(4)+pad(4)+extra(8) = 32
// KEYBDINPUT: wVk(2)+wScan(2)+dwFlags(4)+time(4)+pad(4)+extra(8)+pad2(8) = 32

type mouseINPUT struct {
	dx        int32
	dy        int32
	mouseData uint32
	dwFlags   uint32
	time      uint32
	_         uint32
	extra     uintptr
}

type keyINPUT struct {
	wVk     uint16  // offset 0
	wScan   uint16  // offset 2
	dwFlags uint32  // offset 4
	time    uint32  // offset 8
	_       uint32  // offset 12 — padding to align extra to 8 bytes
	extra   uintptr // offset 16
	_2      [8]byte // offset 24 — pad to 32 bytes to match MOUSEINPUT union size
}

func sendMouseInput(dx, dy int32, flags, data uint32) {
	var inp [40]byte
	// type = INPUT_MOUSE (0)
	*(*mouseINPUT)(unsafe.Pointer(&inp[8])) = mouseINPUT{
		dx: dx, dy: dy, mouseData: data, dwFlags: flags,
	}
	procSendInput.Call(1, uintptr(unsafe.Pointer(&inp[0])), 40)
}

func sendKeyInput(vk uint16, flags uint32) {
	var inp [40]byte
	*(*uint32)(unsafe.Pointer(&inp[0])) = 1 // INPUT_KEYBOARD
	*(*keyINPUT)(unsafe.Pointer(&inp[8])) = keyINPUT{wVk: vk, dwFlags: flags}
	procSendInput.Call(1, uintptr(unsafe.Pointer(&inp[0])), 40)
}

func sendUnicodeKey(text string, flags uint32) {
	units, err := windows.UTF16FromString(text)
	if err != nil {
		return
	}
	for _, unit := range units[:len(units)-1] { // omit terminating NUL
		var inp [40]byte
		*(*uint32)(unsafe.Pointer(&inp[0])) = 1 // INPUT_KEYBOARD
		*(*keyINPUT)(unsafe.Pointer(&inp[8])) = keyINPUT{
			wScan: unit, dwFlags: keyUnicode | flags,
		}
		procSendInput.Call(1, uintptr(unsafe.Pointer(&inp[0])), 40)
	}
}

func releaseModifierKeys() {
	// Release generic and left/right variants. SendInput key-up is harmless
	// when a key is not down, and clears state left behind if the browser,
	// pipe, helper, or agent update disappears between keydown and keyup.
	for _, vk := range []uint16{
		0x10, 0x11, 0x12, // Shift, Ctrl, Alt
		0x5B, 0x5C, // left/right Windows
		0xA0, 0xA1, // left/right Shift
		0xA2, 0xA3, // left/right Ctrl
		0xA4, 0xA5, // left/right Alt
	} {
		sendKeyInput(vk, keyUp)
	}
}

// ── BITMAPINFOHEADER ──────────────────────────────────────────────────────────

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

// ── Screen capture ────────────────────────────────────────────────────────────

// setDPIAware declares this process DPI-aware so GetSystemMetrics(SM_CXSCREEN/
// SM_CYSCREEN) and the GetDC(0)+BitBlt capture in grabJPEG agree on real
// physical screen pixels. Without this, Windows DPI-virtualizes an unaware
// process: GetSystemMetrics reports a scaled-down logical resolution (e.g.
// 1280x720 on a 1920x1080 display at 150% scaling) while BitBlt still reads
// from the real physical framebuffer, so a bitmap sized from the virtualized
// metrics only captures the top-left crop of the real screen — the remote
// viewer then shows a cropped/misaligned image that "doesn't fit" the
// reported resolution.
//
// Deliberately uses only the older, system-DPI-aware SetProcessDPIAware
// (Vista+) rather than SetProcessDpiAwarenessContext's newer per-monitor-v2
// mode — per-monitor-v2 is known to make GetDC(0)+BitBlt return a solid
// black frame on some driver/composition stacks (confirmed live: switching
// to it produced a black remote-desktop feed). System-DPI-aware already
// fixes the metrics/capture mismatch above without that failure mode.
// Must run before the first screenSize()/grabJPEG() call.
func setDPIAware() {
	if procSetProcessDPIAware.Find() == nil {
		procSetProcessDPIAware.Call()
	}
}

func screenSize() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(smCxScreen)
	h, _, _ := procGetSystemMetrics.Call(smCyScreen)
	return int(w), int(h)
}

type monitorRect struct {
	Left, Top, Right, Bottom int32
}

func (r monitorRect) width() int  { return int(r.Right - r.Left) }
func (r monitorRect) height() int { return int(r.Bottom - r.Top) }

func displayMonitors() []monitorRect {
	var result []monitorRect
	callback := syscall.NewCallback(func(_ uintptr, _ uintptr, rect uintptr, _ uintptr) uintptr {
		if rect != 0 {
			r := *(*monitorRect)(unsafe.Pointer(rect))
			if r.width() > 0 && r.height() > 0 {
				result = append(result, r)
			}
		}
		return 1
	})
	procEnumDisplayMonitors.Call(0, 0, callback, 0)
	if len(result) == 0 {
		w, h := screenSize()
		result = []monitorRect{{0, 0, int32(w), int32(h)}}
	}
	return result
}

func grabJPEG(quality int) ([]byte, int, int, error) {
	w, h := screenSize()
	return grabJPEGRegion(quality, monitorRect{0, 0, int32(w), int32(h)})
}

func grabJPEGRegion(quality int, region monitorRect) ([]byte, int, int, error) {
	buf, err := captureGDIRegion(region, systemGDICaptureCall, systemGDIBitmapRead)
	if err != nil {
		return nil, 0, 0, err
	}
	w, h := region.width(), region.height()
	frame, err := encodeBGRAJPEG(buf, w, h, quality)
	if err != nil {
		return nil, 0, 0, err
	}
	return frame, w, h, nil
}

// encodeBGRAJPEG converts a raw top-down BGRA buffer (the format both the
// GDI capture above and the DXGI capture in dxgi_capture.go produce) into a
// JPEG frame, shared by both capture paths.
func encodeBGRAJPEG(buf []byte, w, h, quality int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		o := i * 4
		img.Pix[o+0] = buf[o+2] // R
		img.Pix[o+1] = buf[o+1] // G
		img.Pix[o+2] = buf[o+0] // B
		img.Pix[o+3] = 255      // A
	}

	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// bufAppearsBlack samples a grid of pixels directly from a raw BGRA capture
// buffer (cheaper than decoding the JPEG we're about to encode) to detect a
// BitBlt call that reported success but returned nothing. Sampling rather
// than scanning every pixel keeps this affordable on every captured frame;
// a real desktop is exceedingly unlikely to hit every one of the 96 sampled
// points at pure black.
func bufAppearsBlack(buf []byte, w, h int) bool {
	if w == 0 || h == 0 {
		return false
	}
	for gy := 1; gy <= 8; gy++ {
		for gx := 1; gx <= 12; gx++ {
			x := w * gx / 13
			y := h * gy / 9
			o := (y*w + x) * 4
			if o+2 >= len(buf) {
				continue
			}
			if buf[o] != 0 || buf[o+1] != 0 || buf[o+2] != 0 {
				return false
			}
		}
	}
	return true
}

// ── Clipboard ─────────────────────────────────────────────────────────────────

func clipboardGet() string {
	r, _, _ := procOpenClipboard.Call(0)
	if r == 0 {
		return ""
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicode)
	if h == 0 {
		return ""
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(h)
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p)))
}

func clipboardSet(text string) {
	r, _, _ := procOpenClipboard.Call(0)
	if r == 0 {
		return
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	utf16, err := windows.UTF16FromString(text)
	if err != nil {
		return
	}
	size := uintptr(len(utf16) * 2)
	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, size)
	if hMem == 0 {
		return
	}
	p, _, _ := procGlobalLock.Call(hMem)
	if p == 0 {
		procGlobalFree.Call(hMem)
		return
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(p)), size)
	src := unsafe.Slice((*byte)(unsafe.Pointer(&utf16[0])), size)
	copy(dst, src)
	procGlobalUnlock.Call(hMem)
	procSetClipboardData.Call(cfUnicode, hMem)
}

// ── Input dispatch ────────────────────────────────────────────────────────────

var vkMap = map[string]uint16{
	"Backspace": 0x08, "Tab": 0x09, "Enter": 0x0D, "Shift": 0x10,
	"Control": 0x11, "Alt": 0x12, "Pause": 0x13, "CapsLock": 0x14,
	"Escape": 0x1B, "Space": 0x20, " ": 0x20,
	"PageUp": 0x21, "PageDown": 0x22, "End": 0x23, "Home": 0x24,
	"ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28,
	"Insert": 0x2D, "Delete": 0x2E,
	"F1": 0x70, "F2": 0x71, "F3": 0x72, "F4": 0x73,
	"F5": 0x74, "F6": 0x75, "F7": 0x76, "F8": 0x77,
	"F9": 0x78, "F10": 0x79, "F11": 0x7A, "F12": 0x7B,
	"NumLock": 0x90, "ScrollLock": 0x91, "PrintScreen": 0x2C,
	"Meta": 0x5B, "ContextMenu": 0x5D,
	"0": 0x30, "1": 0x31, "2": 0x32, "3": 0x33, "4": 0x34,
	"5": 0x35, "6": 0x36, "7": 0x37, "8": 0x38, "9": 0x39,
	"a": 0x41, "b": 0x42, "c": 0x43, "d": 0x44, "e": 0x45,
	"f": 0x46, "g": 0x47, "h": 0x48, "i": 0x49, "j": 0x4A,
	"k": 0x4B, "l": 0x4C, "m": 0x4D, "n": 0x4E, "o": 0x4F,
	"p": 0x50, "q": 0x51, "r": 0x52, "s": 0x53, "t": 0x54,
	"u": 0x55, "v": 0x56, "w": 0x57, "x": 0x58, "y": 0x59, "z": 0x5A,
}

var vkCodeMap = map[string]uint16{
	"Backspace": 0x08, "Tab": 0x09, "Enter": 0x0D, "NumpadEnter": 0x0D,
	"ShiftLeft": 0x10, "ShiftRight": 0x10,
	"ControlLeft": 0x11, "ControlRight": 0x11,
	"AltLeft": 0x12, "AltRight": 0x12,
	"Pause": 0x13, "CapsLock": 0x14, "Escape": 0x1B, "Space": 0x20,
	"PageUp": 0x21, "PageDown": 0x22, "End": 0x23, "Home": 0x24,
	"ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28,
	"PrintScreen": 0x2C, "Insert": 0x2D, "Delete": 0x2E,
	"MetaLeft": 0x5B, "MetaRight": 0x5C, "ContextMenu": 0x5D,
	"Numpad0": 0x60, "Numpad1": 0x61, "Numpad2": 0x62, "Numpad3": 0x63,
	"Numpad4": 0x64, "Numpad5": 0x65, "Numpad6": 0x66, "Numpad7": 0x67,
	"Numpad8": 0x68, "Numpad9": 0x69, "NumpadMultiply": 0x6A,
	"NumpadAdd": 0x6B, "NumpadSubtract": 0x6D, "NumpadDecimal": 0x6E,
	"NumpadDivide": 0x6F, "NumLock": 0x90, "ScrollLock": 0x91,
	"Semicolon": 0xBA, "Equal": 0xBB, "Comma": 0xBC, "Minus": 0xBD,
	"Period": 0xBE, "Slash": 0xBF, "Backquote": 0xC0,
	"BracketLeft": 0xDB, "Backslash": 0xDC, "BracketRight": 0xDD, "Quote": 0xDE,
}

func keyboardEventVK(event map[string]interface{}) uint16 {
	code, _ := event["code"].(string)
	if len(code) == 4 && strings.HasPrefix(code, "Key") {
		return uint16(code[3])
	}
	if len(code) == 6 && strings.HasPrefix(code, "Digit") {
		return uint16(code[5])
	}
	if len(code) >= 2 && code[0] == 'F' {
		var n int
		if _, err := fmt.Sscanf(code, "F%d", &n); err == nil && n >= 1 && n <= 24 {
			return uint16(0x6F + n)
		}
	}
	if vk := vkCodeMap[code]; vk != 0 {
		return vk
	}
	key, _ := event["key"].(string)
	vk := vkMap[key]
	if vk == 0 && len(key) == 1 {
		vk = uint16([]byte(strings.ToUpper(key))[0])
	}
	return vk
}

func dispatchInput(event map[string]interface{}, region monitorRect) {
	t, _ := event["type"].(string)
	switch t {
	case "mousemove":
		x, _ := event["x"].(float64)
		y, _ := event["y"].(float64)
		procSetCursorPos.Call(uintptr(int32(x)+region.Left), uintptr(int32(y)+region.Top))

	case "mousedown", "mouseup":
		btn, _ := event["button"].(string)
		var flags uint32
		switch btn {
		case "right":
			if t == "mousedown" {
				flags = mouseRightDown
			} else {
				flags = mouseRightUp
			}
		case "middle":
			if t == "mousedown" {
				flags = mouseMidDown
			} else {
				flags = mouseMidUp
			}
		default:
			if t == "mousedown" {
				flags = mouseLeftDown
			} else {
				flags = mouseLeftUp
			}
		}
		// The browser sends x/y with every mousedown/mouseup (see
		// remote_view.html's canvasXY() spread into the event payload),
		// but this used to discard them and fire the button event at
		// whatever position the cursor was last left at by a separate,
		// earlier "mousemove" message. That relied on the browser's own
		// mousemove throttling (coalesced to its repaint rate) having
		// already landed the real cursor at the exact click pixel by the
		// time the click message arrived -- fine for a slow, deliberate
		// click in open space, but exactly what breaks for small targets
		// (a title bar's minimize button, a narrow list row) where a few
		// stale pixels means the click lands on the wrong element or
		// nothing at all. Combining MOUSEEVENTF_MOVE|ABSOLUTE with the
		// button flag in one SendInput call makes the move and the click
		// atomic and always click exactly where this specific event says,
		// instead of trusting a previous message's cursor position.
		x, _ := event["x"].(float64)
		y, _ := event["y"].(float64)
		procSetCursorPos.Call(uintptr(int32(x)+region.Left), uintptr(int32(y)+region.Top))
		sendMouseInput(0, 0, flags, 0)

	case "scroll":
		delta, _ := event["delta"].(float64)
		data := uint32(-int32(delta) * wheelDelta)
		sendMouseInput(0, 0, mouseWheel, data)

	case "keydown", "keyup":
		key, _ := event["key"].(string)
		ctrl, _ := event["ctrlKey"].(bool)
		alt, _ := event["altKey"].(bool)
		meta, _ := event["metaKey"].(bool)
		// Browser `key` is the character the operator intended, while a
		// physical VK is interpreted through the endpoint's active keyboard
		// layout. Inject printable symbols as Unicode so Shift+2 remains "@"
		// even when the remote machine uses a layout where that key means
		// something else. Letters/digits stay physical for shortcuts and
		// normal modifier behavior.
		if len([]rune(key)) == 1 && !ctrl && !alt && !meta &&
			!strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ", []rune(key)[0]) {
			flags := uint32(0)
			if t == "keyup" {
				flags = keyUp
			}
			sendUnicodeKey(key, flags)
			break
		}
		vk := keyboardEventVK(event)
		if vk != 0 {
			flags := uint32(0)
			if t == "keyup" {
				flags = keyUp
			}
			sendKeyInput(vk, flags)
		}

	case "clipboard_write":
		text, _ := event["text"].(string)
		if text != "" {
			clipboardSet(text)
			sendKeyInput(0x11, 0)     // Ctrl down
			sendKeyInput(0x56, 0)     // V down
			sendKeyInput(0x56, keyUp) // V up
			sendKeyInput(0x11, keyUp) // Ctrl up
		}
	}
}

// ── Relay session ─────────────────────────────────────────────────────────────

var (
	relayMu   sync.Mutex
	relayConn *websocket.Conn
	relayLive *relaySession
)

type relaySession struct {
	stop          chan struct{}
	done          chan struct{}
	stopOnce      sync.Once
	noticeTitle   string
	noticeMessage string
}

func (s *relaySession) stopSession() {
	s.stopOnce.Do(func() { close(s.stop) })
}

// sessionIDFromRelayURL extracts <session_id> from .../agent-relay/<session_id>
// — setupRemoteAccess (commands.go) already validated relayURL's shape before
// ever calling startRemoteRelay, so this is just parsing, not trust.
func sessionIDFromRelayURL(relayURL string) string {
	u, err := url.Parse(relayURL)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(u.Path, "/agent-relay/")
}

// reportRelayFailure tells the server a remote-desktop pairing attempt failed
// and why, so the browser side can show the real reason within a few seconds
// instead of only ever finding out via ws_proxy's 60s PAIR_TIMEOUT generic
// "agent did not connect in time" — every failure branch in runRelaySession
// previously only ever logged locally to agent.log, invisible to the admin
// who actually needs to know why the session didn't come up.
func reportRelayFailure(sessionID, reason string) {
	if sessionID == "" {
		return
	}
	body := map[string]interface{}{"session_id": sessionID, "reason": reason}
	if _, err := apiPostAuth("/api/agent/remote-relay-failed", body); err != nil {
		logWarn("remote-relay-failed report POST failed: %v", err)
	}
}

func reportRemoteConsent(sessionID, status string) {
	if sessionID == "" {
		return
	}
	if _, err := apiPostAuth("/api/agent/remote-consent", map[string]interface{}{
		"session_id": sessionID, "status": status,
	}); err != nil {
		logWarn("remote consent report failed: %v", err)
	}
}

func reportEndpointChat(sessionID, text string) {
	if sessionID == "" || text == "" {
		return
	}
	if _, err := apiPostAuth("/api/agent/remote-chat", map[string]interface{}{
		"session_id": sessionID, "text": text,
	}); err != nil {
		logWarn("remote chat report failed: %v", err)
	}
}

func startRemoteRelay(relayURL, relayAPIKey, noticeTitle, noticeMessage string) error {
	relayMu.Lock()
	defer relayMu.Unlock()

	if relayLive != nil {
		return fmt.Errorf("remote relay session already running")
	}

	session := &relaySession{
		stop: make(chan struct{}), done: make(chan struct{}),
		noticeTitle: noticeTitle, noticeMessage: noticeMessage,
	}
	relayLive = session
	go runRelaySession(relayURL, relayAPIKey, session)
	return nil
}

func stopRemoteRelay() {
	relayMu.Lock()
	session := relayLive
	conn := relayConn
	relayMu.Unlock()
	if session == nil {
		return
	}
	session.stopSession()
	if conn != nil {
		_ = conn.Close()
	}
	select {
	case <-session.done:
	case <-time.After(10 * time.Second):
		// A Windows named-pipe read can remain blocked even after its handles
		// and helper process are closed. Never let that freeze the heartbeat
		// and job loop indefinitely.
		logWarn("Remote relay shutdown timed out; detaching expired session")
		relayMu.Lock()
		if relayLive == session {
			relayLive, relayConn = nil, nil
		}
		relayMu.Unlock()
	}
}

func randomSessionToken() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// notifyUserOfRemoteAccess displays a non-activating Warden notification in
// the active user session. This is transparency, not a substitute for consent.
func notifyUserOfRemoteAccess(title, message string) {
	exePath, exeErr := os.Executable()
	if exeErr != nil {
		logWarn("Could not resolve Agent for remote notice: %v", exeErr)
		return
	}
	if title == "" {
		title = "Remote support is connected"
	}
	if message == "" {
		message = "A Warden administrator can now see this screen."
	}
	helper, err := launchInteractiveHelper(exePath, []string{"--user-notification", title, message, "warning"})
	if err != nil {
		logWarn("Could not notify user of remote access: %v", err)
		return
	}
	go func() {
		if _, finished := helper.wait(20 * time.Second); !finished {
			helper.terminate(2 * time.Second)
		}
	}()
}

// runRelaySession launches the interactive-session helper (remote_helper.go)
// into whichever session owns the active console — this process itself
// normally runs as SYSTEM in session 0, which has no real desktop to capture
// or send input into — and relays between that helper (over two local named
// pipes, see remote_pipe.go) and the WSS connection to the server. The
// helper does the actual GDI capture / SendInput / clipboard access; this
// function never touches the desktop directly.
type remoteHelperBridge struct {
	helper          *interactiveHelper
	desktop         string
	outPipe, inPipe windows.Handle
	outFile, inFile pipeFile
	sw, sh          int
	closeOnce       sync.Once
}

func (b *remoteHelperBridge) close() {
	b.closeOnce.Do(func() {
		windows.CloseHandle(b.outPipe)
		windows.CloseHandle(b.inPipe)
		if b.helper != nil {
			b.helper.terminate(5 * time.Second)
		}
	})
}

func startRemoteHelperBridge(exePath string, session *relaySession, desktop string) (*remoteHelperBridge, error) {
	token := randomSessionToken()
	outName := `\\.\pipe\WardenRemoteOut-` + token
	inName := `\\.\pipe\WardenRemoteIn-` + token
	pipeSDDL := "D:(A;;GA;;;SY)"
	if userSID, err := activeConsoleUserStringSID(); err == nil {
		pipeSDDL = fmt.Sprintf("D:(A;;GA;;;SY)(A;;GRGW;;;%s)", userSID)
	}

	outPipe, err := createPipeServer(outName, windows.PIPE_ACCESS_INBOUND, pipeSDDL)
	if err != nil {
		return nil, fmt.Errorf("create output pipe: %w", err)
	}
	inPipe, err := createPipeServer(inName, windows.PIPE_ACCESS_OUTBOUND, pipeSDDL)
	if err != nil {
		windows.CloseHandle(outPipe)
		return nil, fmt.Errorf("create input pipe: %w", err)
	}
	b := &remoteHelperBridge{outPipe: outPipe, inPipe: inPipe}
	helper, actualDesktop, err := launchRemoteDesktopHelperOn(
		exePath, []string{"--remote-helper", outName, inName}, desktop,
	)
	if err != nil {
		b.close()
		return nil, fmt.Errorf("launch helper: %w", err)
	}
	b.helper, b.desktop = helper, actualDesktop

	const timeout = 20 * time.Second
	step := func(fn func() error) error {
		done := make(chan error, 1)
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					done <- fmt.Errorf("helper handshake panic: %v", recovered)
				}
			}()
			done <- fn()
		}()
		select {
		case err := <-done:
			return err
		case <-session.stop:
			b.close()
			return fmt.Errorf("cancelled")
		case <-time.After(timeout):
			b.close()
			return fmt.Errorf("helper handshake timed out")
		}
	}
	if err := step(func() error { return connectNamedPipeTolerant(outPipe) }); err != nil {
		b.close()
		return nil, err
	}
	if err := step(func() error { return connectNamedPipeTolerant(inPipe) }); err != nil {
		b.close()
		return nil, err
	}
	b.outFile, b.inFile = pipeFile{outPipe}, pipeFile{inPipe}
	if err := step(func() error {
		tag, payload, err := readPipeMsg(b.outFile)
		if err != nil {
			return err
		}
		if tag != 'S' {
			return fmt.Errorf("expected screen size, got %q", tag)
		}
		_, err = fmt.Sscanf(string(payload), "%dx%d", &b.sw, &b.sh)
		return err
	}); err != nil {
		b.close()
		return nil, err
	}
	return b, nil
}

func runRelaySession(relayURL, relayAPIKey string, session *relaySession) {
	sessionID := sessionIDFromRelayURL(relayURL)
	defer func() {
		if recovered := recover(); recovered != nil {
			logError("Recovered panic in remote relay: %v", recovered)
			reportRelayFailure(sessionID, "remote relay stopped after an internal error")
		}
	}()
	defer func() {
		relayMu.Lock()
		if relayLive == session {
			relayLive, relayConn = nil, nil
		}
		relayMu.Unlock()
		close(session.done)
	}()

	exePath, err := os.Executable()
	if err != nil {
		reportRelayFailure(sessionID, fmt.Sprintf("internal error resolving agent path: %v", err))
		return
	}
	// Remote access is administrator-authorized and must also work while the
	// endpoint is unattended, locked, or at Winlogon.
	bridge, err := startRemoteHelperBridge(exePath, session, "")
	if err != nil {
		logWarn("Remote relay helper startup failed: %v", err)
		reportRelayFailure(sessionID, fmt.Sprintf("could not start remote desktop: %v", err))
		return
	}
	notifyUserOfRemoteAccess(session.noticeTitle, session.noticeMessage)

	headers := http.Header{}
	headers.Set("X-Agent-Key", relayAPIKey)
	proofRequest, proofErr := http.NewRequest(http.MethodGet, relayURL, nil)
	if proofErr == nil {
		proofRequest.Header = headers
		proofErr = addDeviceRequestProof(proofRequest, nil)
	}
	if proofErr != nil {
		bridge.close()
		reportRelayFailure(sessionID, "device request proof unavailable")
		return
	}
	conn, _, err := websocket.DefaultDialer.Dial(relayURL, headers)
	if err != nil {
		bridge.close()
		reportRelayFailure(sessionID, fmt.Sprintf("could not reach the Warden relay server: %v", err))
		return
	}
	defer conn.Close()
	defer bridge.close()
	relayMu.Lock()
	relayConn = conn
	relayMu.Unlock()
	// Browser control messages are tiny JSON documents. Bound the read size
	// so a faulty or compromised peer cannot make the endpoint allocate an
	// arbitrarily large WebSocket message.
	conn.SetReadLimit(1024 * 1024)

	var writerMu sync.Mutex
	writeWS := func(kind int, data []byte) error {
		writerMu.Lock()
		defer writerMu.Unlock()
		return conn.WriteMessage(kind, data)
	}
	inputCh := make(chan []byte, 128)
	wsDead := make(chan struct{})
	go func() {
		defer close(wsDead)
		defer func() {
			if recovered := recover(); recovered != nil {
				logError("Recovered panic in remote WebSocket reader: %v", recovered)
			}
		}()
		for {
			kind, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if kind == websocket.TextMessage {
				select {
				case inputCh <- data:
				case <-session.stop:
					return
				}
			}
		}
	}()

	chatSlots := make(chan struct{}, 2)
	for {
		initMsg, _ := json.Marshal(map[string]interface{}{"type": "init", "w": bridge.sw, "h": bridge.sh})
		if err := writeWS(websocket.TextMessage, initMsg); err != nil {
			break
		}
		logInfo("Remote relay helper active on %s desktop (%dx%d)", bridge.desktop, bridge.sw, bridge.sh)

		helperDead := make(chan struct{})
		switchDesktop := make(chan struct{}, 1)
		var helperDeadOnce sync.Once
		markHelperDead := func() { helperDeadOnce.Do(func() { close(helperDead) }) }
		var pump sync.WaitGroup
		pump.Add(1)
		go func(current *remoteHelperBridge) {
			defer pump.Done()
			defer func() {
				if recovered := recover(); recovered != nil {
					logError("Recovered panic in remote frame pump: %v", recovered)
					markHelperDead()
				}
			}()
			for {
				tag, payload, err := readPipeMsg(current.outFile)
				if err != nil {
					markHelperDead()
					return
				}
				if tag == 'F' {
					// 1-byte frame-type prefix (0x00 = full, 0x01 = partial —
					// see remote_view.html's binary message handler) lets the
					// browser tell full and partial frames apart on the same
					// WS binary channel.
					err = writeWS(websocket.BinaryMessage, append([]byte{0x00}, payload...))
				} else if tag == 'P' {
					// payload is already x,y,w,h (8 bytes) + jpeg, exactly
					// what the browser expects after the type byte — see
					// buildPartialFramePayload in remote_pipe.go.
					err = writeWS(websocket.BinaryMessage, append([]byte{0x01}, payload...))
				} else if tag == 'S' {
					var width, height int
					if _, scanErr := fmt.Sscanf(string(payload), "%dx%d", &width, &height); scanErr == nil {
						bridge.sw, bridge.sh = width, height
						msg, _ := json.Marshal(map[string]interface{}{"type": "init", "w": width, "h": height})
						err = writeWS(websocket.TextMessage, msg)
					}
				} else if tag == 'M' {
					var monitors interface{}
					if json.Unmarshal(payload, &monitors) == nil {
						msg, _ := json.Marshal(map[string]interface{}{"type": "monitors", "monitors": monitors})
						err = writeWS(websocket.TextMessage, msg)
					}
				} else if tag == 'C' {
					msg, _ := json.Marshal(map[string]interface{}{"type": "clipboard_update", "text": string(payload)})
					err = writeWS(websocket.TextMessage, msg)
				} else if tag == 'D' {
					msg, _ := json.Marshal(map[string]interface{}{"type": "drop_target", "path": string(payload)})
					err = writeWS(websocket.TextMessage, msg)
				} else if tag == 'L' {
					// The helper can't reliably write agent.log itself (see
					// remote_helper.go's capture-failure comment), so it sends
					// log lines here instead — this process's logger does
					// have a working, SYSTEM-writable agent.log.
					logWarn("remote helper (%s desktop): %s", current.desktop, string(payload))
				} else if tag == 'X' {
					select {
					case switchDesktop <- struct{}{}:
					default:
					}
					markHelperDead()
					return
				}
				if err != nil {
					markHelperDead()
					return
				}
			}
		}(bridge)

		restart := false
		nextDesktop := ""
	loop:
		for {
			select {
			case <-session.stop:
				bridge.close()
				pump.Wait()
				return
			case <-wsDead:
				break loop
			case <-helperDead:
				restart = true
				select {
				case <-switchDesktop:
					if bridge.desktop == "default" {
						nextDesktop = "winlogon"
					} else {
						nextDesktop = "default"
					}
					logInfo("Remote relay input desktop changed; switching helper from %s to %s", bridge.desktop, nextDesktop)
				default:
				}
				break loop
			case data := <-inputCh:
				var evt map[string]interface{}
				if json.Unmarshal(data, &evt) == nil {
					eventType, _ := evt["type"].(string)
					if eventType == "process_list" {
						ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
						cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
							`Get-Process | Sort-Object CPU -Descending | Select-Object -First 200 Id,ProcessName,CPU,WorkingSet64 | ConvertTo-Json -Compress`)
						out, cmdErr := cmd.Output()
						cancel()
						var processes interface{} = []interface{}{}
						if cmdErr == nil {
							if err := json.Unmarshal(out, &processes); err != nil {
								cmdErr = err
							}
						}
						response := map[string]interface{}{"type": "process_list", "processes": processes}
						if cmdErr != nil {
							response = map[string]interface{}{"type": "process_error", "error": cmdErr.Error()}
						}
						encoded, _ := json.Marshal(response)
						_ = writeWS(websocket.TextMessage, encoded)
						continue
					}
					if eventType == "process_kill" {
						pidFloat, ok := evt["pid"].(float64)
						pid := int(pidFloat)
						if !ok || pid <= 4 {
							encoded, _ := json.Marshal(map[string]interface{}{"type": "process_error", "error": "invalid or protected process id"})
							_ = writeWS(websocket.TextMessage, encoded)
							continue
						}
						cmdErr := exec.Command("taskkill.exe", "/PID", strconv.Itoa(pid), "/F").Run()
						response := map[string]interface{}{"type": "process_killed", "pid": pid}
						if cmdErr != nil {
							response = map[string]interface{}{"type": "process_error", "error": cmdErr.Error()}
						}
						encoded, _ := json.Marshal(response)
						_ = writeWS(websocket.TextMessage, encoded)
						continue
					}
					if eventType == "reboot_reconnect" {
						encoded, _ := json.Marshal(map[string]interface{}{"type": "rebooting"})
						_ = writeWS(websocket.TextMessage, encoded)
						_ = exec.Command("shutdown.exe", "/r", "/t", "5", "/d", "p:4:1", "/c", "Warden remote support reboot").Start()
						continue
					}
					if eventType == "ctrl_alt_del" {
						response := map[string]interface{}{"type": "ctrl_alt_del_sent"}
						if sasErr := sendSecureAttentionSequence(); sasErr != nil {
							logWarn("Remote Ctrl+Alt+Delete failed: %v", sasErr)
							response = map[string]interface{}{"type": "remote_error", "error": "Ctrl+Alt+Delete could not be sent"}
						}
						encoded, _ := json.Marshal(response)
						_ = writeWS(websocket.TextMessage, encoded)
						continue
					}
					if eventType == "support_chat" {
						text, _ := evt["text"].(string)
						if text == "" {
							continue
						}
						text = limitResultText(text, 16*1024, "chat prompt")
						select {
						case chatSlots <- struct{}{}:
						default:
							encoded, _ := json.Marshal(map[string]interface{}{"type": "chat_error", "error": "too many chat requests are already running"})
							_ = writeWS(websocket.TextMessage, encoded)
							continue
						}
						go func(prompt string) {
							defer func() {
								<-chatSlots
								if recovered := recover(); recovered != nil {
									logError("Recovered panic in endpoint chat: %v", recovered)
								}
							}()
							reply, replyErr := requestEndpointChatReply(prompt)
							if replyErr == nil && reply != "" {
								reportEndpointChat(sessionID, reply)
							}
							response := map[string]interface{}{"type": "chat_reply", "text": reply}
							if replyErr != nil {
								response = map[string]interface{}{"type": "chat_error", "error": replyErr.Error()}
							}
							encoded, _ := json.Marshal(response)
							_ = writeWS(websocket.TextMessage, encoded)
						}(text)
						continue
					}
					if err := writePipeMsg(bridge.inFile, 'I', data); err != nil {
						restart = true
						break loop
					}
				}
			}
		}
		bridge.close()
		pump.Wait()
		if !restart {
			break
		}

		// Windows briefly tears down the old desktop during sign-in/sign-out.
		// Retry the local helper while leaving the already-paired WebSocket open.
		for {
			select {
			case <-session.stop:
				return
			case <-wsDead:
				return
			case <-time.After(750 * time.Millisecond):
			}
			bridge, err = startRemoteHelperBridge(exePath, session, nextDesktop)
			if err == nil {
				break
			}
			logWarn("Remote relay helper restart pending: %v", err)
		}
	}
	logInfo("Remote relay session ended")
}
