package main

import (
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestWardenScrollThumbIsBoundedAndReachesBothEnds(t *testing.T) {
	for _, height := range []int32{20, 80, 270} {
		for _, total := range []int32{0, 1, 4, 50, 1000000} {
			for _, page := range []int32{0, 1, 4, 12} {
				for _, first := range []int32{-5, 0, 5, 1000000} {
					m := wardenScrollGeometry(total, page, first, height, 28)
					if m.thumb > height || m.thumb < 1 || m.top < 0 || m.top+m.thumb > height {
						t.Fatalf("invalid thumb: %+v", m)
					}
					if m.position(-100, 0) != 0 || m.position(height+100, 0) != m.maxFirst && m.height > m.thumb {
						t.Fatalf("invalid end: %+v", m)
					}
				}
			}
		}
	}
}
func TestWardenScrollNativeEditKeepsLongMessagesReachable(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	window, _, _ := uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString("STATIC"))), 0, 0x80000000, 0, 0, 600, 550, 0, 0, 0, 0)
	if window == 0 {
		t.Fatal("test window failed")
	}
	defer uiDestroyWindow.Call(window)
	font, _, _ := uiCreateFont.Call(^uintptr(15), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(font)
	u := &wardenUI{window: window, font: font, scale: 1, width: 600, height: 550}
	u.edit, _, _ = uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString("EDIT"))), uintptr(unsafe.Pointer(uiString(strings.Repeat("A line of the test message\r\n", 70)))), 0x40000000|0x4|0x40|0x800, 36, 152, 516, 270, window, 20, 0, 0)
	if u.edit == 0 {
		t.Fatal("test edit failed")
	}
	uiSendMessage.Call(u.edit, 0x30, font, 1)
	previous := currentWardenUI
	currentWardenUI = u
	defer func() { currentWardenUI = previous }()
	u.editOriginal, _, _ = user32DLL.NewProc("SetWindowLongPtrW").Call(u.edit, ^uintptr(3), uiEditCallback)
	if u.editOriginal == 0 {
		t.Fatal("edit subclass failed")
	}
	m := u.scrollMetrics()
	if m.maxFirst < 50 {
		t.Fatalf("long text lost: %+v", m)
	}
	u.scrollTo(m.maxFirst)
	first, _, _ := uiSendMessage.Call(u.edit, 0xce, 0, 0)
	if int32(first) != m.maxFirst {
		t.Fatalf("last page unreachable: %d != %d", first, m.maxFirst)
	}
	uiSendMessage.Call(u.edit, 0x20a, 120<<16, 0)
	moved, _, _ := uiSendMessage.Call(u.edit, 0xce, 0, 0)
	if moved >= first {
		t.Fatal("mouse wheel does not scroll upward")
	}
	u.scrollTo(0)
	first, _, _ = uiSendMessage.Call(u.edit, 0xce, 0, 0)
	if first != 0 {
		t.Fatal("first page unreachable")
	}
	if u.result != 0 || u.approval {
		t.Fatal("scrolling changed consent state")
	}
}
