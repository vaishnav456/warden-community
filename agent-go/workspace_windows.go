package main

// A user-session launcher, not a privileged command surface. The circle opens
// helpdesk only; future modules cannot supply arbitrary executables or URLs.
import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var workspaceCallback = windows.NewCallback(workspaceWindowProc)
var workspaceDotCallback = windows.NewCallback(workspaceDotProc)
var workspaceDotOriginal uintptr
var workspacePanel *floatingWorkspace

type floatingWorkspace struct {
	window, dot, report, refresh, vpn, passwords, close, font, smallFont uintptr
	work                                                                 uiRect
	size, width, height                                                  int32
	expanded, ready, rendering                                           bool
	anchorX, anchorY, pressX, pressY, offsetX, offsetY                   int32
	pressed, dragging, dockLeft                                          bool
	hoverID                                                              uintptr
	actionOriginal                                                       map[uintptr]uintptr
	fadeStart                                                            time.Time
	reduceMotion                                                         bool
	activity                                                             workspaceActivity
	activityKnown                                                        bool
	activityAt                                                           time.Time
	activityPoll                                                         workspaceActivityPoll
	position                                                             workspacePoint
	layingOut                                                            bool
	closePressed                                                         bool
	trayMode                                                             bool
	trayIcon                                                             uintptr
	trayLabel                                                            string
	taskbarCreated                                                       uint32
	helpdeskPoll                                                         workspaceHelpdeskPoll
}

// Native owner-draw buttons retain keyboard navigation and accessible names.
type workspaceDrawItem struct {
	ControlType, ControlID, ItemID, Action, State uint32
	Window, DC                                    uintptr
	Rect                                          uiRect
	Data                                          uintptr
}
type workspaceMenuItem struct {
	id         uintptr
	label      string
	x, y, size int32
	disabled   bool
}

func workspaceMenuItems(d int32) []workspaceMenuItem {
	s, pad := d/4, d/14
	mid := (d - s) / 2
	return []workspaceMenuItem{
		{102, "Helpdesk", mid, pad, s, false},
		{101, "Requests", pad, mid, s, false},
		{105, "VPN\nSoon", d - s - pad, mid, s, true},
		{106, "Passwords\nSoon", mid, d - s - pad, s, true},
		{103, "Close", (d - d/6) / 2, (d - d/6) / 2, d / 6, false},
	}
}

var workspaceActionCallback = windows.NewCallback(workspaceActionProc)

type workspaceMouseTrack struct {
	Size, Flags uint32
	Window      uintptr
	HoverTime   uint32
}

func workspaceActionProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	p := workspacePanel
	if p == nil {
		result, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
		return result
	}
	if hwnd == p.close {
		switch message {
		case 0x0201:
			p.closePressed = true
			user32DLL.NewProc("SetCapture").Call(hwnd)
			return 0
		case 0x0202:
			pressed := p.closePressed
			p.closePressed = false
			user32DLL.NewProc("ReleaseCapture").Call()
			var bounds uiRect
			user32DLL.NewProc("GetClientRect").Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
			x, y := int32(int16(lParam&0xffff)), int32(int16((lParam>>16)&0xffff))
			if pressed && workspacePointInside(bounds, x, y) {
				p.layout(false)
			}
			return 0
		case 0x0215, 0x001f:
			p.closePressed = false
		}
	}
	switch message {
	case 0x0200:
		id, _, _ := user32DLL.NewProc("GetDlgCtrlID").Call(hwnd)
		if p.hoverID != id {
			p.hoverID = id
			track := workspaceMouseTrack{Flags: 2, Window: hwnd}
			track.Size = uint32(unsafe.Sizeof(track))
			user32DLL.NewProc("TrackMouseEvent").Call(uintptr(unsafe.Pointer(&track)))
			p.render()
		}
	case 0x02a3:
		id, _, _ := user32DLL.NewProc("GetDlgCtrlID").Call(hwnd)
		if p.hoverID == id {
			p.hoverID = 0
			p.render()
		}
	}
	result, _, _ := user32DLL.NewProc("CallWindowProcW").Call(p.actionOriginal[hwnd], hwnd, uintptr(message), wParam, lParam)
	if message == 0x0007 || message == 0x0008 {
		p.render()
	}
	return result
}

// Bounded ease-out fade; no recurring animation or idle timer.
func workspaceFadeAlpha(elapsed time.Duration) byte {
	if elapsed >= 180*time.Millisecond {
		return 255
	}
	if elapsed < 0 {
		elapsed = 0
	}
	t := float64(elapsed) / float64(180*time.Millisecond)
	eased := 1 - (1-t)*(1-t)*(1-t)
	return byte(180 + 75*eased)
}
func (p *floatingWorkspace) open() {
	if p.expanded {
		return
	}
	if !p.reduceMotion {
		p.fadeStart = time.Now()
	}
	p.layout(true)
	uiSetFocus.Call(p.close)
	if !p.fadeStart.IsZero() {
		uiSetTimer.Call(p.window, 7, 16, 0)
	}
}

type workspacePoint struct{ X, Y int32 }

func workspacePointInside(bounds uiRect, x, y int32) bool {
	return x >= bounds.Left && x < bounds.Right && y >= bounds.Top && y < bounds.Bottom
}

func workspaceBounds(work uiRect, x, y, width, height int32) uiRect {
	if width > work.Right-work.Left {
		width = work.Right - work.Left
	}
	if height > work.Bottom-work.Top {
		height = work.Bottom - work.Top
	}
	if x < work.Left {
		x = work.Left
	}
	if y < work.Top {
		y = work.Top
	}
	if x > work.Right-width {
		x = work.Right - width
	}
	if y > work.Bottom-height {
		y = work.Bottom - height
	}
	return uiRect{x, y, x + width, y + height}
}

func (p *floatingWorkspace) snap() {
	p.dockLeft = p.anchorX < p.work.Left+(p.work.Right-p.work.Left)/2
	p.anchorX = p.work.Right - p.size/2 - 8
	if p.dockLeft {
		p.anchorX = p.work.Left + p.size/2 + 8
	}
	p.layout(false)
}

func workspaceDotProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	p := workspacePanel
	if p != nil {
		var cursor workspacePoint
		switch message {
		case 0x0201: // mouse down: hold the dot, don't activate until release.
			if ok, _, _ := user32DLL.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&cursor))); ok == 0 {
				break
			}
			p.pressed, p.dragging = true, false
			p.pressX, p.pressY = cursor.X, cursor.Y
			p.offsetX, p.offsetY = cursor.X-p.anchorX, cursor.Y-p.anchorY
			user32DLL.NewProc("SetCapture").Call(hwnd)
			return 0
		case 0x0200:
			if !p.pressed {
				if p.hoverID != 100 {
					p.hoverID = 100
					track := workspaceMouseTrack{Flags: 2, Window: hwnd}
					track.Size = uint32(unsafe.Sizeof(track))
					user32DLL.NewProc("TrackMouseEvent").Call(uintptr(unsafe.Pointer(&track)))
					p.render()
				}
				break
			}
			if ok, _, _ := user32DLL.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&cursor))); ok == 0 {
				break
			}
			dx, dy := cursor.X-p.pressX, cursor.Y-p.pressY
			if dx*dx+dy*dy > 36 {
				p.dragging = true
			}
			if p.dragging {
				p.anchorX, p.anchorY = cursor.X-p.offsetX, cursor.Y-p.offsetY
				p.layout(false)
			}
			return 0
		case 0x0202:
			if !p.pressed {
				break
			}
			dragged := p.dragging
			p.pressed, p.dragging = false, false
			user32DLL.NewProc("ReleaseCapture").Call()
			p.snap()
			if !dragged {
				p.open()

			}
			return 0
		case 0x02a3:
			if p.hoverID == 100 {
				p.hoverID = 0
				p.render()
			}
			return 0
		case 0x0215, 0x001f: // lost capture / cancellation never opens support.
			if p.pressed {
				p.pressed, p.dragging = false, false
				p.snap()
			}
			return 0
		}
	}
	result, _, _ := user32DLL.NewProc("CallWindowProcW").Call(workspaceDotOriginal, hwnd, uintptr(message), wParam, lParam)
	return result
}

func (p *floatingWorkspace) layout(expanded bool) {
	// Commit pixels, position and size together; never move the old dot first.
	p.layingOut = true
	if !expanded {
		user32DLL.NewProc("KillTimer").Call(p.window, 7)
		p.fadeStart = time.Time{}
		p.hoverID = 0
	}
	p.expanded = expanded
	width, height := p.size, p.size
	if expanded {
		width, height = p.width, p.height
	}
	x := p.anchorX - width/2
	y := p.anchorY - height/2
	if expanded {
		x = p.work.Right - width - 8
		if p.dockLeft {
			x = p.work.Left + 8
		}
	}
	bounds := workspaceBounds(p.work, x, y, width, height)
	x, y, width, height = bounds.Left, bounds.Top, bounds.Right-bounds.Left, bounds.Bottom-bounds.Top
	if !expanded {
		p.anchorX, p.anchorY = x+width/2, y+height/2
	}
	p.position = workspacePoint{x, y}
	show := uintptr(0)
	if expanded {
		show = 5
	}
	for _, child := range []uintptr{p.report, p.refresh, p.vpn, p.passwords, p.close} {
		uiShowWindow.Call(child, show)
	}
	dotShow := uintptr(5)
	if expanded {
		dotShow = 0
	}
	uiShowWindow.Call(p.dot, dotShow)

	p.layingOut = false
	if !p.render() {
		logWarn("Workspace composition failed")
	}
	// Z-order only: composition already committed the geometry.
	user32DLL.NewProc("SetWindowPos").Call(p.window, ^uintptr(0), 0, 0, 0, 0, 0x0013)
}

func workspaceLaunch(argument string) {
	// Fixed internal modes only; no supplied executable, URL or remote command.
	if argument != "--request-support" && argument != "--support-status" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, argument)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if cmd.Start() == nil {
		go cmd.Wait()
	}
}

func workspaceWindowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	p := workspacePanel
	if p != nil {
		switch message {
		case 0x0111:
			if lParam == 0 {
				break
			}
			switch wParam & 0xffff {
			case 100:
				p.open()

			case 101:
				p.layout(false)
				workspaceLaunch("--support-status")
			case 102:
				p.layout(false)
				workspaceLaunch("--request-support")
			case 103:
				p.layout(false)
			}
			return 0

		case 0x002b: // WM_DRAWITEM: custom circular controls, not legacy buttons.
			if lParam != 0 {
				p.render()
				return 1
			}
		case 0x0113:
			if wParam == 8 {
				if p.activityKnown && time.Since(p.activityAt) > 10*time.Second {
					p.activityKnown = false
					p.render()
				}
				p.pollActivity()
				return 0
			}
			if wParam == 7 {
				if time.Since(p.fadeStart) >= 180*time.Millisecond {
					user32DLL.NewProc("KillTimer").Call(p.window, 7)
					p.fadeStart = time.Time{}
				}
				p.render()
				return 0
			}
		case 0x8002:
			p.applyActivity()
			return 0
		case 0x007e, 0x02e0: // display/DPI change: keep the circle on the work area.
			uiWorkArea.Call(0x30, 0, uintptr(unsafe.Pointer(&p.work)), 0)
			p.layout(false)
			return 0
		case 0x0010: // Close collapses rather than terminating the launcher.
			p.layout(false)
			return 0
		case 0x0002:
			uiPostQuit.Call(0)
			return 0
		}
	}
	result, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

func runRadialWorkspace() int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// One launcher per signed-in account/session; never expose a SYSTEM UI.
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
	procSetProcessDPIAware.Call()
	graphicsToken, graphicsErr := workspaceStartGraphics()
	if graphicsErr != nil || graphicsToken == 0 {
		return 1
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(graphicsToken)
	p := &floatingWorkspace{size: 56, width: 340, height: 340, actionOriginal: make(map[uintptr]uintptr)}
	var animationEnabled int32
	if ok, _, _ := uiWorkArea.Call(0x1042, 0, uintptr(unsafe.Pointer(&animationEnabled)), 0); ok == 0 || animationEnabled == 0 {
		p.reduceMotion = true
	}
	if ok, _, _ := uiWorkArea.Call(0x30, 0, uintptr(unsafe.Pointer(&p.work)), 0); ok == 0 {
		return 1
	}
	if p.width > p.work.Right-p.work.Left-16 {
		p.width = p.work.Right - p.work.Left - 16
	}
	if p.height > p.work.Bottom-p.work.Top-16 {
		p.height = p.work.Bottom - p.work.Top - 16
	}
	if p.height < p.width {
		p.width = p.height
	}
	p.height = p.width
	if p.width < 240 {
		return 1
	}
	p.anchorX, p.anchorY = p.work.Right-p.size/2-8, p.work.Top+(p.work.Bottom-p.work.Top)/2
	instance, _, _ := kernel32DLL.NewProc("GetModuleHandleW").Call(0)
	name := uiString("WardenFloatingWorkspace")
	brush, _, _ := uiCreateBrush.Call(0x001b2e36)
	defer procDeleteObject.Call(brush)
	class := uiClass{Size: uint32(unsafe.Sizeof(uiClass{})), Callback: workspaceCallback, Instance: instance, Name: name, Background: brush}
	if atom, _, _ := uiRegisterClass.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		return 1
	}
	defer user32DLL.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(name)), instance)
	workspacePanel = p
	defer func() { workspacePanel = nil }()
	p.window, _, _ = uiCreateWindow.Call(0x00080088, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(uiString("Warden workspace"))), 0x80000000,
		0, 0, uintptr(p.width), uintptr(p.height), 0, 0, instance, 0)
	if p.window == 0 {
		return 1
	}
	p.font, _, _ = uiCreateFont.Call(uintptr(^uintptr(14)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(p.font)
	p.smallFont, _, _ = uiCreateFont.Call(^uintptr(10), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(p.smallFont)
	child := func(class, text string, style uintptr, x, y, w, h int32, id uintptr) uintptr {
		handle, _, _ := uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString(class))), uintptr(unsafe.Pointer(uiString(text))), 0x50000000|style,
			uintptr(x), uintptr(y), uintptr(w), uintptr(h), p.window, id, instance, 0)
		uiSendMessage.Call(handle, 0x30, p.font, 1)
		return handle
	}
	p.dot = child("BUTTON", "Warden workspace — drag to move, click to open", 0x10000|0x000b, 0, 0, p.size, p.size, 100)
	if p.dot == 0 {
		uiDestroyWindow.Call(p.window)
		return 1
	}
	workspaceDotOriginal, _, _ = user32DLL.NewProc("SetWindowLongPtrW").Call(p.dot, ^uintptr(3), workspaceDotCallback)
	if workspaceDotOriginal == 0 {
		uiDestroyWindow.Call(p.window)
		return 1
	}

	for _, item := range workspaceMenuItems(p.width) {
		style := uintptr(0x10000 | 0x000b)
		if item.disabled {
			style |= 0x08000000
		}
		h := child("BUTTON", item.label, style, item.x, item.y, item.size, item.size, item.id)
		if h == 0 {
			uiDestroyWindow.Call(p.window)
			return 1
		}
		original, _, _ := user32DLL.NewProc("SetWindowLongPtrW").Call(h, ^uintptr(3), workspaceActionCallback)
		if original == 0 {
			uiDestroyWindow.Call(p.window)
			return 1
		}
		p.actionOriginal[h] = original
		switch item.id {
		case 101:
			p.refresh = h
		case 102:
			p.report = h
		case 103:
			p.close = h
		case 105:
			p.vpn = h
		case 106:
			p.passwords = h
		}
	}
	p.ready = true
	p.layout(false)
	uiShowWindow.Call(p.window, 0) // consume service helper SW_HIDE startup setting.
	uiShowWindow.Call(p.window, 4) // show without stealing focus.
	p.pollActivity()
	uiSetTimer.Call(p.window, 8, 3000, 0) // Bounded, local-only read; never an HTTP poll.
	var message uiMessage
	for {
		result, _, _ := uiGetMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) <= 0 {
			break
		}
		if message.Message == 0x100 && message.WParam == 27 {
			p.layout(false)
			continue
		}
		if handled, _, _ := uiDialogMessage.Call(p.window, uintptr(unsafe.Pointer(&message))); handled != 0 {
			continue
		}
		uiTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		uiDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
	}
	return 0
}

func runWorkspaceLauncher(stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var helper *interactiveHelper
	var identity string
	defer func() {
		if helper != nil {
			helper.terminate(2 * time.Second)
		}
	}()
	for {
		session, err := activeConsoleSessionID()
		username, userErr := sessionUsername(session)
		next := ""
		if err == nil && userErr == nil && username != "" {
			next = username + ":" + fmtSession(session)
		}
		if next != identity {
			if helper != nil {
				helper.terminate(2 * time.Second)
				helper = nil
			}
			identity = next
		}
		// Recover a crashed user helper on the bounded 30-second poll, without
		// changing the installed service or ever falling back to SYSTEM UI.
		if helper != nil && !helper.isAlive() {
			helper.terminate(2 * time.Second)
			helper = nil
		}
		if next != "" && helper == nil {
			exe, exeErr := os.Executable()
			if exeErr == nil {
				helper, _ = launchInteractiveHelper(exe, []string{"--workspace"})
			}
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func fmtSession(session uint32) string { return fmt.Sprint(session) }
