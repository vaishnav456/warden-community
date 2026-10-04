package main

// The native EDIT still owns text, selection, wrapping, keyboard and wheel
// scrolling. This control only translates the scrollbar's visual interaction
// into bounded EM_LINESCROLL messages; it cannot approve anything.
import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var uiScrollCallback = windows.NewCallback(wardenScrollProc)
var uiEditCallback = windows.NewCallback(wardenEditProc)

type wardenScrollMetrics struct{ total, page, first, height, thumb, top, maxFirst int32 }

func wardenScrollGeometry(total, page, first, height, minThumb int32) wardenScrollMetrics {
	if total < 1 {
		total = 1
	}
	if page < 1 {
		page = 1
	}
	if height < 1 {
		height = 1
	}
	maxFirst := total - page
	if maxFirst < 0 {
		maxFirst = 0
	}
	if first < 0 {
		first = 0
	}
	if first > maxFirst {
		first = maxFirst
	}
	thumb := height
	if total > page {
		thumb = int32(int64(height) * int64(page) / int64(total))
	}
	if thumb < minThumb {
		thumb = minThumb
	}
	if thumb > height {
		thumb = height
	}
	top := int32(0)
	if maxFirst > 0 {
		top = int32(int64(height-thumb) * int64(first) / int64(maxFirst))
	}
	return wardenScrollMetrics{total, page, first, height, thumb, top, maxFirst}
}
func (m wardenScrollMetrics) position(y, offset int32) int32 {
	travel := m.height - m.thumb
	if travel <= 0 || m.maxFirst <= 0 {
		return 0
	}
	top := y - offset
	if top < 0 {
		top = 0
	}
	if top > travel {
		top = travel
	}
	return int32((int64(top)*int64(m.maxFirst) + int64(travel)/2) / int64(travel))
}
func (u *wardenUI) scrollMetrics() wardenScrollMetrics {
	if u.ticket != nil {
		return wardenScrollGeometry(u.ticket.total, u.ticket.page, u.ticket.offset, u.ticket.page, u.px(28))
	}
	total, _, _ := uiSendMessage.Call(u.edit, 0xba, 0, 0)
	first, _, _ := uiSendMessage.Call(u.edit, 0xce, 0, 0)
	var rect uiRect
	uiSendMessage.Call(u.edit, 0xb2, 0, uintptr(unsafe.Pointer(&rect)))
	dc, _, _ := user32DLL.NewProc("GetDC").Call(u.edit)
	lineHeight := u.px(20)
	if dc != 0 {
		old, _, _ := procSelectObject.Call(dc, u.font)
		var extent workspacePoint
		if ok, _, _ := gdi32DLL.NewProc("GetTextExtentPoint32W").Call(dc, uintptr(unsafe.Pointer(uiString("Ag"))), 2, uintptr(unsafe.Pointer(&extent))); ok != 0 && extent.Y > 0 {
			lineHeight = extent.Y
		}
		procSelectObject.Call(dc, old)
		user32DLL.NewProc("ReleaseDC").Call(u.edit, dc)
	}
	if lineHeight < 1 {
		lineHeight = 1
	}
	page := (rect.Bottom - rect.Top) / lineHeight
	return wardenScrollGeometry(int32(total), page, int32(first), u.height-u.px(280), u.px(28))
}
func (u *wardenUI) refreshScroll() {
	if u.scroll == 0 || (u.edit == 0 && u.ticket == nil) {
		return
	}
	// Keep native wrapping/keyboard scrolling, with no unthemed non-client bar.
	if u.ticket == nil {
		user32DLL.NewProc("ShowScrollBar").Call(u.edit, 1, 0)
	}
	m := u.scrollMetrics()
	show := uintptr(0)
	if m.maxFirst > 0 {
		show = 5
	}
	uiShowWindow.Call(u.scroll, show)
	user32DLL.NewProc("InvalidateRect").Call(u.scroll, 0, 0)
}
func (u *wardenUI) scrollTo(first int32) {
	if u.ticket != nil {
		u.ticket.scrollTo(first)
		return
	}
	m := u.scrollMetrics()
	if first < 0 {
		first = 0
	}
	if first > m.maxFirst {
		first = m.maxFirst
	}
	uiSendMessage.Call(u.edit, 0xb6, 0, uintptr(first-m.first))
	u.refreshScroll()
}
func wardenEditProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	u := currentWardenUI
	if u == nil {
		r, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
		return r
	}
	if message == 0x020a {
		u.scrollWheelRemainder += int32(int16(wParam >> 16))
		steps := u.scrollWheelRemainder / 120
		u.scrollWheelRemainder %= 120
		if steps != 0 {
			var lines uint32 = 3
			uiWorkArea.Call(0x68, 0, uintptr(unsafe.Pointer(&lines)), 0)
			m := u.scrollMetrics()
			if lines == 0xffffffff {
				lines = uint32(m.page)
			}
			target := int64(m.first) - int64(steps)*int64(lines)
			if target < 0 {
				target = 0
			}
			if target > int64(m.maxFirst) {
				target = int64(m.maxFirst)
			}
			u.scrollTo(int32(target))
		}
		return 0
	}
	result, _, _ := user32DLL.NewProc("CallWindowProcW").Call(u.editOriginal, hwnd, uintptr(message), wParam, lParam)
	switch message {
	case 0x020a, 0x0100, 0x0102, 0x000c, 0x0115, 0x00b6, 0x00b7, 0x0300, 0x0302, 0x0303:
		u.refreshScroll()
	}
	return result
}
func (u *wardenUI) scrollY(hwnd uintptr) int32 {
	var cursor workspacePoint
	user32DLL.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&cursor)))
	user32DLL.NewProc("ScreenToClient").Call(hwnd, uintptr(unsafe.Pointer(&cursor)))
	return cursor.Y
}
func wardenScrollProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	u := currentWardenUI
	if u == nil {
		r, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
		return r
	}
	switch message {
	case 0x0201:
		uiSetFocus.Call(hwnd)
		y := u.scrollY(hwnd)
		m := u.scrollMetrics()
		if y >= m.top && y < m.top+m.thumb {
			u.scrollDragging = true
			u.scrollOffset = y - m.top
			user32DLL.NewProc("SetCapture").Call(hwnd)
		} else if y < m.top {
			u.scrollTo(m.first - m.page)
		} else {
			u.scrollTo(m.first + m.page)
		}
		u.refreshScroll()
		return 0
	case 0x0200:
		if !u.scrollHover {
			u.scrollHover = true
			track := workspaceMouseTrack{Flags: 2, Window: hwnd}
			track.Size = uint32(unsafe.Sizeof(track))
			user32DLL.NewProc("TrackMouseEvent").Call(uintptr(unsafe.Pointer(&track)))
			u.refreshScroll()
		}
		if u.scrollDragging {
			u.scrollTo(u.scrollMetrics().position(u.scrollY(hwnd), u.scrollOffset))
		}
		return 0
	case 0x0202, 0x0215, 0x001f:
		if u.scrollDragging {
			u.scrollDragging = false
			if message == 0x0202 {
				user32DLL.NewProc("ReleaseCapture").Call()
			}
			u.refreshScroll()
		}
		return 0
	case 0x02a3:
		u.scrollHover = false
		u.refreshScroll()
		return 0
	case 0x020a:
		if u.ticket != nil {
			uiSendMessage.Call(u.ticket.panel, uintptr(message), wParam, lParam)
			return 0
		}
		uiSendMessage.Call(u.edit, uintptr(message), wParam, lParam)
		u.refreshScroll()
		return 0
	case 0x0087: // DLGC_WANTARROWS, retaining the native button's keyboard semantics.
		result, _, _ := user32DLL.NewProc("CallWindowProcW").Call(u.scrollOriginal, hwnd, uintptr(message), wParam, lParam)
		return result | 1
	case 0x0100:
		m := u.scrollMetrics()
		target := m.first
		switch wParam {
		case 38:
			target--
			if u.ticket != nil {
				target = m.first - u.px(32)
			}
		case 40:
			target++
			if u.ticket != nil {
				target = m.first + u.px(32)
			}
		case 33:
			target -= m.page
		case 34:
			target += m.page
		case 36:
			target = 0
		case 35:
			target = m.maxFirst
		default:
			break
		}
		if wParam == 38 || wParam == 40 || wParam == 33 || wParam == 34 || wParam == 36 || wParam == 35 {
			u.scrollTo(target)
			return 0
		}
	}
	result, _, _ := user32DLL.NewProc("CallWindowProcW").Call(u.scrollOriginal, hwnd, uintptr(message), wParam, lParam)
	if message == 7 || message == 8 {
		u.refreshScroll()
	}
	return result
}
func (u *wardenUI) paintScroll(item *workspaceDrawItem) {
	w, h := item.Rect.Right-item.Rect.Left, item.Rect.Bottom-item.Rect.Top
	s := workspaceNewSurface(w, h)
	if s == nil {
		return
	}
	defer s.close()
	workspaceGDIPlus.NewProc("GdipGraphicsClear").Call(s.graphics, 0xff1e3542)
	m := u.scrollMetrics()
	trackWidth := u.px(4)
	if u.scrollHover || u.scrollDragging || item.State&0x10 != 0 {
		trackWidth = u.px(7)
	}
	if trackWidth > w {
		trackWidth = w
	}
	if trackWidth < 2 {
		trackWidth = 2
	}
	x := (w - trackWidth) / 2
	s.roundedRect(x, 0, trackWidth, h, trackWidth/2, 0xff294652)
	color := uint32(0xff648f9f)
	if u.scrollHover || u.scrollDragging || item.State&0x10 != 0 {
		color = 0xffa1dce5
	}
	s.roundedRect(x, m.top, trackWidth, m.thumb, trackWidth/2, color)
	workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
	gdi32DLL.NewProc("BitBlt").Call(item.DC, uintptr(item.Rect.Left), uintptr(item.Rect.Top), uintptr(w), uintptr(h), s.dc, 0, 0, 0x00cc0020)
}
