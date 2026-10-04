package main

import (
	"runtime"
	"testing"
)

func TestWardenBrandMarkContainsFrameRouteAndSpark(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	token, err := workspaceStartGraphics()
	if err != nil || token == 0 {
		t.Fatal("GDI+ startup failed", err)
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(token)
	s := workspaceNewSurface(40, 40)
	if s == nil {
		t.Fatal("brand surface failed")
	}
	defer s.close()
	s.wardenMark(0, 0, 40, 0xffffffff)
	workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
	for _, p := range [][2]int{{34, 16}, {20, 19}, {20, 10}} {
		if s.bits[(p[1]*40+p[0])*4+3] < 100 {
			t.Fatalf("missing brand component at %v", p)
		}
	}
	if s.bits[(30*40+20)*4+3] != 0 {
		t.Fatal("mark should retain open shield interior")
	}
}
