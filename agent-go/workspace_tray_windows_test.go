package main

import (
	"runtime"
	"testing"
	"unsafe"
)

func TestWorkspaceTrayNativeIconAndABI(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(workspaceNotifyIcon{}) != 976 {
		t.Fatalf("NOTIFYICONDATA ABI size %d", unsafe.Sizeof(workspaceNotifyIcon{}))
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	token, err := workspaceStartGraphics()
	if err != nil || token == 0 {
		t.Fatal("graphics startup", err)
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(token)
	for _, state := range []workspaceActivity{{}, {RemoteActive: true}, {RecordingSupported: true, RecordingActive: true}} {
		icon := workspaceTrayIcon(true, state)
		if icon == 0 {
			t.Fatal("native tray icon creation failed")
		}
		user32DLL.NewProc("DestroyIcon").Call(icon)
	}
}
