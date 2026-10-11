package main

import (
	"bytes"
	"errors"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type fakeDXGIFrame struct {
	present, mouse        int64
	accumulated, metadata uint32
	dirty                 []dxgiRect
	moves                 []dxgiMoveRect
	dirtyError, moveError bool
	mapError              bool
}

type fakeDXGIObject struct{ vtable *[48]uintptr }

// The fake COM objects exercise the same acquire/metadata/copy/map/release
// sequence as real capture, without opening a display or touching input.
type fakeDXGICapture struct {
	t                                                *testing.T
	frames                                           []fakeDXGIFrame
	next                                             int
	current                                          fakeDXGIFrame
	duplVT, resourceVT, textureVT, contextVT         [48]uintptr
	dupl, resource, texture, context                 fakeDXGIObject
	staging                                          byte
	pixels                                           []byte
	capturer                                         dxgiCapturer
	copies, maps, unmaps, queries, dirtyReads, moves int
	frameReleases, resourceReleases, textureReleases int
}

func newFakeDXGICapture(t *testing.T, frames ...fakeDXGIFrame) *fakeDXGICapture {
	f := &fakeDXGICapture{t: t, frames: frames, pixels: make([]byte, 2*24)}
	f.dupl.vtable, f.resource.vtable = &f.duplVT, &f.resourceVT
	f.texture.vtable, f.context.vtable = &f.textureVT, &f.contextVT
	// Four BGRA pixels per row with eight padding bytes in the mapped texture.
	for row := 0; row < 2; row++ {
		for col := 0; col < 4; col++ {
			copy(f.pixels[row*24+col*4:], []byte{byte(row*4 + col + 1), 20, 30, 255})
		}
	}
	f.duplVT[8] = syscall.NewCallback(func(this, timeout, infoAddress, resourceAddress uintptr) uintptr {
		if timeout != 500 || f.next >= len(f.frames) {
			t.Errorf("unexpected acquisition timeout %d/frame %d", timeout, f.next)
			return uintptr(hrDXGIAccessLost)
		}
		f.current = f.frames[f.next]
		f.next++
		*(*dxgiOutduplFrameInfo)(unsafe.Pointer(infoAddress)) = dxgiOutduplFrameInfo{
			LastPresentTime: f.current.present, LastMouseUpdateTime: f.current.mouse,
			AccumulatedFrames: f.current.accumulated, TotalMetadataBufferSize: f.current.metadata,
		}
		*(*unsafe.Pointer)(unsafe.Pointer(resourceAddress)) = unsafe.Pointer(&f.resource)
		return 0
	})
	f.duplVT[9] = syscall.NewCallback(func(this, size, buffer, required uintptr) uintptr {
		f.dirtyReads++
		if f.current.dirtyError {
			return 0x80004005
		}
		*(*uint32)(unsafe.Pointer(required)) = uint32(len(f.current.dirty)) * uint32(unsafe.Sizeof(dxgiRect{}))
		copy(unsafe.Slice((*dxgiRect)(unsafe.Pointer(buffer)), len(f.current.dirty)), f.current.dirty)
		return 0
	})
	f.duplVT[10] = syscall.NewCallback(func(this, size, buffer, required uintptr) uintptr {
		f.moves++
		if f.current.moveError {
			return 0x80004005
		}
		*(*uint32)(unsafe.Pointer(required)) = uint32(len(f.current.moves)) * uint32(unsafe.Sizeof(dxgiMoveRect{}))
		copy(unsafe.Slice((*dxgiMoveRect)(unsafe.Pointer(buffer)), len(f.current.moves)), f.current.moves)
		return 0
	})
	f.duplVT[14] = syscall.NewCallback(func(this uintptr) uintptr {
		f.frameReleases++
		return 0
	})
	f.resourceVT[0] = syscall.NewCallback(func(this, iid, out uintptr) uintptr {
		f.queries++
		*(*unsafe.Pointer)(unsafe.Pointer(out)) = unsafe.Pointer(&f.texture)
		return 0
	})
	f.resourceVT[2] = syscall.NewCallback(func(this uintptr) uintptr {
		f.resourceReleases++
		return 0
	})
	f.textureVT[2] = syscall.NewCallback(func(this uintptr) uintptr {
		f.textureReleases++
		return 0
	})
	f.contextVT[47] = syscall.NewCallback(func(this, destination, source uintptr) uintptr {
		f.copies++
		if destination != uintptr(unsafe.Pointer(&f.staging)) || source != uintptr(unsafe.Pointer(&f.texture)) {
			t.Error("copied incorrect texture resources")
		}
		return 0x80004005 // CopyResource returns void.
	})
	f.contextVT[14] = syscall.NewCallback(func(this, resource, subresource, mapType, flags, out uintptr) uintptr {
		f.maps++
		if f.current.mapError {
			return 0x80004005
		}
		*(*d3d11MappedSubresource)(unsafe.Pointer(out)) = d3d11MappedSubresource{
			PData: uintptr(unsafe.Pointer(&f.pixels[0])), RowPitch: 24,
		}
		return 0
	})
	f.contextVT[15] = syscall.NewCallback(func(this, resource, subresource uintptr) uintptr {
		f.unmaps++
		return 0x80004005 // Unmap returns void.
	})
	f.capturer = dxgiCapturer{
		dupl: unsafe.Pointer(&f.dupl), context: unsafe.Pointer(&f.context), staging: unsafe.Pointer(&f.staging),
		width: 4, height: 2,
	}
	return f
}

func TestDXGICursorOnlyAcquisitionBootstrapsThenSkipsGPUCopy(t *testing.T) {
	fake := newFakeDXGICapture(t,
		fakeDXGIFrame{mouse: 1},
		fakeDXGIFrame{mouse: 2},
		fakeDXGIFrame{present: 3, dirty: []dxgiRect{{Left: 0, Top: 0, Right: 1, Bottom: 1}}},
	)
	defer runtime.KeepAlive(fake)
	buf, w, h, _, err := fake.capturer.grabBGRA()
	want := append(append([]byte(nil), fake.pixels[:16]...), fake.pixels[24:40]...)
	if err != nil || w != 4 || h != 2 || !bytes.Equal(buf, want) || !fake.capturer.hasSnapshot {
		t.Fatalf("initial cursor acquisition did not supply baseline: %dx%d error %v", w, h, err)
	}
	buf, w, h, dirty, err := fake.capturer.grabBGRA()
	if !errors.Is(err, errNoNewFrame) || buf != nil || dirty != nil || w != 0 || h != 0 {
		t.Fatalf("cursor-only update became desktop frame: %dx%d error %v", w, h, err)
	}
	if fake.copies != 1 || fake.maps != 1 || fake.unmaps != 1 || fake.queries != 1 || fake.dirtyReads != 1 || fake.moves != 1 {
		t.Fatalf("cursor-only update did capture work: %+v", fake)
	}
	if fake.frameReleases != 2 || fake.resourceReleases != 2 || fake.textureReleases != 1 {
		t.Fatalf("cursor-only acquisition leaked frame/resource: %+v", fake)
	}
	_, _, _, dirty, err = fake.capturer.grabBGRA()
	if err != nil || len(dirty) != 1 || fake.copies != 2 || fake.frameReleases != 3 || fake.resourceReleases != 3 {
		t.Fatalf("real desktop update was skipped or leaked: error %v, %+v", err, fake)
	}
}

func TestDXGIRealUpdateWithMetadataFailureStillSuppliesFullSnapshot(t *testing.T) {
	for _, metadata := range []string{"dirty", "move"} {
		t.Run(metadata, func(t *testing.T) {
			frame := fakeDXGIFrame{present: 2, dirtyError: metadata == "dirty", moveError: metadata == "move"}
			fake := newFakeDXGICapture(t, fakeDXGIFrame{present: 1}, frame)
			defer runtime.KeepAlive(fake)
			_, _, _, _, err := fake.capturer.grabBGRA()
			if err != nil {
				t.Fatal(err)
			}
			buf, w, h, dirty, err := fake.capturer.grabBGRA()
			if err != nil || len(buf) != 32 || w != 4 || h != 2 || len(dirty) != 0 || fake.copies != 2 {
				t.Fatalf("metadata failure lost desktop snapshot: %dx%d error %v", w, h, err)
			}
			var state remoteCaptureState
			now := time.Unix(100, 0)
			state.sentFull(now, w, h)
			state.remember(buf, w, h)
			_, _, uw, uh, haveDirty := unionDirtyRects(dirty, w, h)
			if !state.needsFull(now, haveDirty, uw*uh, w*h, w, h) {
				t.Fatal("missing metadata allowed a delta")
			}
			if fake.frameReleases != 2 || fake.resourceReleases != 2 || fake.textureReleases != 2 || fake.unmaps != 2 {
				t.Fatalf("metadata fallback leaked frame/resource: %+v", fake)
			}
		})
	}
}

func TestDXGICursorOnlySkipRequiresConsistentFrameMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame fakeDXGIFrame
		skip  bool
	}{
		{"pointer-only", fakeDXGIFrame{mouse: 2}, true},
		{"desktop-timestamp", fakeDXGIFrame{mouse: 2, present: 2}, false},
		{"accumulated-desktop-frame", fakeDXGIFrame{mouse: 2, accumulated: 1}, false},
		{"desktop-metadata", fakeDXGIFrame{mouse: 2, metadata: 16, dirty: []dxgiRect{{Right: 1, Bottom: 1}}}, false},
		{"metadata-read-failure", fakeDXGIFrame{mouse: 2, metadata: 16, dirtyError: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDXGICapture(t, fakeDXGIFrame{present: 1}, tc.frame)
			defer runtime.KeepAlive(fake)
			if _, _, _, _, err := fake.capturer.grabBGRA(); err != nil {
				t.Fatal(err)
			}
			buf, w, h, dirty, err := fake.capturer.grabBGRA()
			if tc.skip {
				if !errors.Is(err, errNoNewFrame) || buf != nil || fake.copies != 1 {
					t.Fatalf("consistent pointer-only event was captured: error %v", err)
				}
			} else {
				if err != nil || len(buf) != 32 || w != 4 || h != 2 || fake.copies != 2 || len(dirty) != 0 {
					t.Fatalf("uncertain update did not supply full snapshot: %dx%d error %v", w, h, err)
				}
			}
			if fake.frameReleases != 2 || fake.resourceReleases != 2 {
				t.Fatal("classification path leaked acquired frame/resource")
			}
		})
	}
}

func TestDXGIFailedUpdatedSnapshotRetriesOnCursorOnlyAcquisition(t *testing.T) {
	fake := newFakeDXGICapture(t,
		fakeDXGIFrame{present: 1}, fakeDXGIFrame{present: 2, mapError: true}, fakeDXGIFrame{mouse: 3},
	)
	defer runtime.KeepAlive(fake)
	if _, _, _, _, err := fake.capturer.grabBGRA(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := fake.capturer.grabBGRA(); err == nil || fake.capturer.hasSnapshot {
		t.Fatal("failed updated capture retained a current snapshot")
	}
	buf, _, _, _, err := fake.capturer.grabBGRA()
	if err != nil || len(buf) != 32 || !fake.capturer.hasSnapshot || fake.copies != 3 || fake.maps != 3 {
		t.Fatalf("cursor-only update did not recover failed snapshot: error %v, %+v", err, fake)
	}
	if fake.frameReleases != 3 || fake.resourceReleases != 3 || fake.textureReleases != 3 || fake.unmaps != 2 {
		t.Fatalf("failed capture leaked frame/resource: %+v", fake)
	}
}

func TestDXGIMoveOnlyUpdateKeepsDestinationMetadata(t *testing.T) {
	fake := newFakeDXGICapture(t, fakeDXGIFrame{
		present: 1, moves: []dxgiMoveRect{{DestinationRect: dxgiRect{Left: 1, Top: 0, Right: 3, Bottom: 1}}},
	})
	defer runtime.KeepAlive(fake)
	_, w, h, dirty, err := fake.capturer.grabBGRA()
	x, y, uw, uh, ok := unionDirtyRects(dirty, w, h)
	if err != nil || !ok || x != 1 || y != 0 || uw != 2 || uh != 1 {
		t.Fatalf("move-only update was dropped: %d,%d %dx%d error %v", x, y, uw, uh, err)
	}
}

func TestDXGIBaselineResetRecapturesAnUnchangedDesktop(t *testing.T) {
	fake := newFakeDXGICapture(t, fakeDXGIFrame{present: 1}, fakeDXGIFrame{mouse: 2})
	defer runtime.KeepAlive(fake)
	if _, _, _, _, err := fake.capturer.grabBGRA(); err != nil {
		t.Fatal(err)
	}
	// The helper discarded the old monitor/source baseline. An unchanged
	// desktop must provide a fresh DXGI image rather than keep a GDI bootstrap.
	fake.capturer.hasSnapshot = false
	buf, w, h, dirty, err := fake.capturer.grabBGRA()
	if err != nil || len(buf) != 32 || w != 4 || h != 2 || len(dirty) != 0 || fake.copies != 2 {
		t.Fatalf("reset baseline could not recover static desktop: %dx%d error %v", w, h, err)
	}
}
