package main

import (
	"bytes"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestRemoteCaptureIdleReplaysCurrentSnapshotAfterPartial(t *testing.T) {
	now := time.Unix(100, 0)
	var state remoteCaptureState
	original := bytes.Repeat([]byte{10, 20, 30, 255}, 4)
	state.remember(original, 2, 2)
	state.sentFull(now, 2, 2)
	current := append([]byte(nil), original...)
	copy(current[4:8], []byte{90, 80, 70, 255})
	state.remember(current, 2, 2)
	state.sentPartial(now.Add(time.Second))
	if state.shouldReplay(now.Add(2*time.Second), 2, 2) {
		t.Fatal("replayed before idle interval")
	}
	if !state.shouldReplay(now.Add(3*time.Second), 2, 2) {
		t.Fatal("idle refresh not requested")
	}
	if !bytes.Equal(state.pixels, current) || bytes.Equal(state.pixels, original) {
		t.Fatal("idle replay lost a change previously sent as a delta")
	}
	if state.needsBootstrap() {
		t.Fatal("healthy DXGI would fall back to GDI")
	}
}

func TestRemoteCaptureGDIBootstrapAndFallbackRequireResync(t *testing.T) {
	now := time.Unix(100, 0)
	var state remoteCaptureState
	if !state.needsBootstrap() {
		t.Fatal("initial GDI bootstrap unavailable")
	}
	state.sentGDI(now)
	if state.needsBootstrap() {
		t.Fatal("idle capture repeatedly substitutes GDI")
	}
	state.remember(make([]byte, 16), 2, 2)
	if !state.needsFull(now, true, 1, 4, 2, 2) {
		t.Fatal("first DXGI frame was a delta")
	}
	state.sentFull(now, 2, 2)
	if state.needsFull(now, true, 1, 4, 2, 2) {
		t.Fatal("valid small delta requires unnecessary full frame")
	}
	state.sentGDI(now.Add(time.Second))
	if len(state.pixels) != 0 || state.baseline {
		t.Fatal("GDI left an incompatible DXGI baseline")
	}
	state.remember(make([]byte, 16), 2, 2)
	if !state.needsFull(now.Add(time.Second), true, 1, 4, 2, 2) {
		t.Fatal("DXGI delta patched a GDI frame")
	}
}

func TestRemoteCaptureResetDropsPreviousMonitorOrGeneration(t *testing.T) {
	now := time.Unix(100, 0)
	var state remoteCaptureState
	state.remember(bytes.Repeat([]byte{255}, 16), 2, 2)
	state.sentFull(now, 2, 2)
	state.reset() // monitor selection or DXGI access-loss/reinitialization
	if state.shouldReplay(now.Add(5*time.Second), 2, 2) || len(state.pixels) != 0 {
		t.Fatal("replayed prior monitor")
	}
	if !state.needsBootstrap() {
		t.Fatal("new capture generation cannot bootstrap")
	}
	state.remember(make([]byte, 36), 3, 3)
	if !state.needsFull(now, true, 1, 9, 3, 3) {
		t.Fatal("new monitor did not require full baseline")
	}
}

func TestRemoteCaptureFailedDXGIAndGDIMustResynchronize(t *testing.T) {
	now := time.Unix(100, 0)
	var state remoteCaptureState
	state.remember(make([]byte, 16), 2, 2)
	state.sentFull(now, 2, 2)
	// The next acquired frame was consumed but not encoded or mapped.
	// GDI subsequently fails too, so sentGDI is never reached.
	state.invalidateBaseline()
	if state.baseline || len(state.pixels) != 0 || state.needsBootstrap() {
		t.Fatal("failed capture retained a stale image or requested another GDI bootstrap")
	}
	state.remember(make([]byte, 16), 2, 2)
	if !state.needsFull(now, true, 1, 4, 2, 2) {
		t.Fatal("delta omitted pixels from the consumed but unsent frame")
	}
}

func TestRemoteCaptureScaleChangeAndBlackDesktop(t *testing.T) {
	now := time.Unix(100, 0)
	var state remoteCaptureState
	black := make([]byte, 4*4*4)
	state.remember(black, 4, 4)
	state.sentFull(now, 4, 4)
	if !state.shouldReplay(now, 2, 2) {
		t.Fatal("idle viewport resize did not refresh full frame")
	}
	if !state.needsFull(now, true, 1, 16, 2, 2) {
		t.Fatal("viewport resize allowed mismatched partial sampling")
	}
	state.sentFull(now, 2, 2)
	if state.needsFull(now, true, 1, 16, 2, 2) {
		t.Fatal("unchanged scale cannot send a delta")
	}
	if !state.shouldReplay(now.Add(2*time.Second), 2, 2) || state.needsBootstrap() {
		t.Fatal("legitimate black desktop was mistaken for a failed capture")
	}
}

func TestRemoteCaptureMoveDestinationsAreTransmitted(t *testing.T) {
	// A moved window can have no dirty rectangles at all. The acquired full
	// texture already has its pixels at the destination, so send that area.
	moves := []dxgiMoveRect{{DestinationRect: dxgiRect{Left: 3, Top: 1, Right: 5, Bottom: 3}}}
	rects := captureUpdateRects(nil, moves)
	x, y, w, h, ok := unionDirtyRects(rects, 8, 4)
	if !ok || x != 3 || y != 1 || w != 2 || h != 2 {
		t.Fatalf("move omitted: %d,%d %dx%d", x, y, w, h)
	}
	surface := make([]byte, 8*4*4)
	for row := 1; row < 3; row++ {
		for col := 3; col < 5; col++ {
			surface[(row*8+col)*4] = 99
		}
	}
	crop := cropBGRA(surface, 8, x, y, w, h)
	for i := 0; i < len(crop); i += 4 {
		if crop[i] != 99 {
			t.Fatal("move destination did not use the current full surface")
		}
	}
	rects = captureUpdateRects([]dxgiRect{{Left: 0, Top: 0, Right: 1, Bottom: 1}}, moves)
	x, y, w, h, ok = unionDirtyRects(rects, 8, 4)
	if !ok || x != 0 || y != 0 || w != 5 || h != 3 {
		t.Fatalf("dirty + move coverage wrong: %d,%d %dx%d", x, y, w, h)
	}
}

func TestRemoteCaptureVoidCOMCallIgnoresReturnRegister(t *testing.T) {
	var calls int
	callback := syscall.NewCallback(func(this, dst, src uintptr) uintptr {
		calls++
		if dst != 17 || src != 23 {
			t.Errorf("unexpected resource arguments %d %d", dst, src)
		}
		return 0x80004005 // unspecified RAX contents; a void call cannot return failure
	})
	vtable := [1]uintptr{callback}
	object := struct{ vtable *[1]uintptr }{&vtable}
	comCallVoid(unsafe.Pointer(&object), 0, 17, 23)
	runtime.KeepAlive(vtable)
	runtime.KeepAlive(object)
	if calls != 1 {
		t.Fatalf("CopyResource call count %d", calls)
	}
}
