package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var ticketInputCallback = windows.NewCallback(ticketInputProc)

type ticketMeasureItem struct {
	Type, ID, Item, Width, Height uint32
	Data                          uintptr
}

func (f *ticketFormUI) close() {
	if f.inputBrush != 0 {
		procDeleteObject.Call(f.inputBrush)
		f.inputBrush = 0
	}
}

func ticketFieldColors(focused bool) (uint32, uint32) {
	rim := uint32(0xff466171)
	if focused {
		rim = 0xff8fd4df
	}
	return 0xff172b36, rim
}

func ticketFieldSurface(u *wardenUI, w, h int32, focused bool) *workspaceSurface {
	s := workspaceNewSurface(w, h)
	if s == nil {
		return nil
	}
	workspaceGDIPlus.NewProc("GdipGraphicsClear").Call(s.graphics, 0xff1e3542)
	fill, rim := ticketFieldColors(focused)
	s.roundedRect(0, 0, w, h, u.px(8), rim)
	s.roundedRect(1, 1, w-2, h-2, u.px(7), fill)
	return s
}

func (f *ticketFormUI) paintFields(dc uintptr) {
	var rect uiRect
	user32DLL.NewProc("GetClientRect").Call(f.panel, uintptr(unsafe.Pointer(&rect)))
	f.u.fill(dc, rect, 0x0042351e)
	focus, _, _ := user32DLL.NewProc("GetFocus").Call()
	for _, c := range f.controls {
		if !c.visible || len(c.options) > 0 {
			continue
		}
		s := ticketFieldSurface(f.u, rect.Right, c.height, focus == c.input)
		if s == nil {
			continue
		}
		workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
		gdi32DLL.NewProc("BitBlt").Call(dc, 0, uintptr(c.top+f.u.px(28)-f.offset), uintptr(s.width), uintptr(s.height), s.dc, 0, 0, 0x00cc0020)
		s.close()
	}
}

func (f *ticketFormUI) choiceSurface(c ticketControl, w, h int32, focused bool) *workspaceSurface {
	s := ticketFieldSurface(f.u, w, h, focused)
	if s == nil {
		return nil
	}
	label := f.value(c)
	if label == "" && len(c.options) > 0 {
		label = c.options[0]
	}
	s.textLeft(label, f.u.px(12), 0, w-f.u.px(48), h, f.u.font, 0xffedf7f9)
	x, y := w-f.u.px(22), h/2
	s.line(x-f.u.px(4), y-f.u.px(2), x, y+f.u.px(2), 0xff8fd4df)
	s.line(x, y+f.u.px(2), x+f.u.px(4), y-f.u.px(2), 0xff8fd4df)
	return s
}

func (f *ticketFormUI) paintChoice(item *workspaceDrawItem) {
	for _, c := range f.controls {
		if c.input != item.Window || len(c.options) == 0 {
			continue
		}
		w, h := item.Rect.Right-item.Rect.Left, item.Rect.Bottom-item.Rect.Top
		s := workspaceNewSurface(w, h)
		if s == nil {
			return
		}
		defer s.close()
		fill := uint32(0xff172b36)
		if item.State&1 != 0 {
			fill = 0xff2b6979
		}
		workspaceGDIPlus.NewProc("GdipGraphicsClear").Call(s.graphics, uintptr(fill))
		if int(item.ItemID) < len(c.options) {
			s.textLeft(c.options[item.ItemID], f.u.px(12), 0, w-f.u.px(24), h, f.u.font, 0xffedf7f9)
		}
		workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
		gdi32DLL.NewProc("BitBlt").Call(item.DC, uintptr(item.Rect.Left), uintptr(item.Rect.Top), uintptr(w), uintptr(h), s.dc, 0, 0, 0x00cc0020)
		return
	}
}

// Native controls still handle typing, IME, accessibility, selection and all
// dropdown keyboard/mouse behaviour. Only their visual chrome is replaced.
func ticketInputProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	f := currentTicketForm
	if f != nil {
		for _, c := range f.controls {
			if c.input != hwnd || c.original == 0 {
				continue
			}
			result, _, _ := user32DLL.NewProc("CallWindowProcW").Call(c.original, hwnd, uintptr(message), wParam, lParam)
			if message == 7 || message == 8 {
				user32DLL.NewProc("InvalidateRect").Call(f.panel, 0, 0)
				user32DLL.NewProc("InvalidateRect").Call(hwnd, 0, 0)
			}
			if len(c.options) > 0 && (message == 0xf || message == 0x318) {
				var rect uiRect
				user32DLL.NewProc("GetClientRect").Call(hwnd, uintptr(unsafe.Pointer(&rect)))
				focus, _, _ := user32DLL.NewProc("GetFocus").Call()
				s := f.choiceSurface(c, rect.Right, rect.Bottom, focus == hwnd)
				if s != nil {
					dc := wParam
					if message == 0xf {
						dc, _, _ = user32DLL.NewProc("GetDC").Call(hwnd)
					}
					if dc != 0 {
						workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
						gdi32DLL.NewProc("BitBlt").Call(dc, 0, 0, uintptr(s.width), uintptr(s.height), s.dc, 0, 0, 0x00cc0020)
						if message == 0xf {
							user32DLL.NewProc("ReleaseDC").Call(hwnd, dc)
						}
					}
					s.close()
				}
			}
			return result
		}
	}
	result, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}
