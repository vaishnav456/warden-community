package main

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type fakeGDICapture struct {
	t             *testing.T
	selected      uintptr
	threadID      uint32
	events        []string
	operations    []uintptr
	readLines     []uintptr
	readErrors    []error
	black         bool
	copyFails     []bool
	restoreFails  bool
	reads, copies int
}

func (f *fakeGDICapture) call(proc *windows.LazyProc, args ...uintptr) (uintptr, uintptr, error) {
	f.t.Helper()
	if f.threadID == 0 {
		f.threadID = windows.GetCurrentThreadId()
	}
	runtime.Gosched()
	if windows.GetCurrentThreadId() != f.threadID {
		f.t.Fatal("capture changed OS thread")
	}
	event := ""
	result := uintptr(1)
	var err error
	switch proc {
	case procGetDC:
		event = "getDC"
		result = 1
	case procCreateCompatibleDC:
		event = "createDC"
		result = 2
		f.selected = 4
	case procCreateCompatibleBitmap:
		event = "createBitmap"
		result = 3
	case procSelectObject:
		if args[1] == 3 {
			event = "selectCapture"
		} else {
			event = "restoreBitmap"
		}
		if args[1] == 4 && f.restoreFails {
			result = 0
			err = windows.ERROR_INVALID_HANDLE
			break
		}
		result = f.selected
		f.selected = args[1]
	case procBitBlt:
		event = "copy"
		if f.selected != 3 {
			f.t.Fatal("BitBlt destination bitmap was not selected")
		}
		f.operations = append(f.operations, args[8])
		if f.copies < len(f.copyFails) && f.copyFails[f.copies] {
			result = 0
			err = windows.ERROR_INVALID_PARAMETER
		}
		f.copies++
	case procGdiFlush:
		event = "flush"
	case procDeleteObject:
		event = "deleteBitmap"
		if f.selected == 3 {
			f.t.Fatal("deleted bitmap while still selected")
		}
	case procDeleteDC:
		event = "deleteDC"
		f.selected = 0
	case procReleaseDC:
		event = "releaseDC"
	default:
		f.t.Fatal("unexpected GDI operation")
	}
	f.events = append(f.events, event)
	return result, 0, err
}

func (f *fakeGDICapture) readBitmap(dc, bitmap uintptr, buf []byte, bi *bitmapInfoHeader) (uintptr, error) {
	f.t.Helper()
	if windows.GetCurrentThreadId() != f.threadID {
		f.t.Fatal("readback changed OS thread")
	}
	if dc != 1 || bitmap != 3 {
		f.t.Fatal("readback used incorrect handles")
	}
	if f.selected == 3 {
		f.t.Fatal("GetDIBits called while bitmap selected")
	}
	if bi.biHeight >= 0 || bi.biBitCount != 32 || bi.biPlanes != 1 {
		f.t.Fatal("capture not top-down32-bit")
	}
	if !f.black {
		for i := 0; i < len(buf); i += 4 {
			copy(buf[i:i+4], []byte{20, 40, 80, 255})
		}
	}
	result := uintptr(-bi.biHeight)
	var err error
	if f.reads < len(f.readLines) {
		result = f.readLines[f.reads]
	}
	if f.reads < len(f.readErrors) {
		err = f.readErrors[f.reads]
	}
	f.reads++
	f.events = append(f.events, "read")
	return result, err
}

func TestGDICaptureDeselectsBeforeReadAndCleansUp(t *testing.T) {
	fake := &fakeGDICapture{t: t}
	buf, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap)
	if err != nil || len(buf) != 48 {
		t.Fatalf("capture bytes%d error%v", len(buf), err)
	}
	expected := "getDC,createDC,createBitmap,selectCapture,copy,flush,restoreBitmap,read,deleteBitmap,deleteDC,releaseDC"
	if strings.Join(fake.events, ",") != expected {
		t.Fatalf("wrong GDI sequence %v", fake.events)
	}
	if len(fake.operations) != 1 || fake.operations[0] != srccopy|captureBlt {
		t.Fatalf("wrong capture operation %v", fake.operations)
	}
}

func TestGDICaptureRejectsZeroOrPartialScanlinesWithoutLastError(t *testing.T) {
	for _, lines := range []uintptr{0, 1, 2} {
		t.Run(string(rune('0'+lines)), func(t *testing.T) {
			fake := &fakeGDICapture{t: t, readLines: []uintptr{lines, lines}}
			buf, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap)
			if err == nil || buf != nil {
				t.Fatal("incomplete readback became a successful image")
			}
			if fake.reads != 2 {
				t.Fatalf("SRCCOPY recovery not attempted: reads%d", fake.reads)
			}
			if !strings.HasSuffix(strings.Join(fake.events, ","), "deleteBitmap,deleteDC,releaseDC") {
				t.Fatalf("leaked GDI resources %v", fake.events)
			}
		})
	}
}

func TestGDICaptureFallsBackWhenCaptureBltFails(t *testing.T) {
	fake := &fakeGDICapture{t: t, copyFails: []bool{true, false}}
	buf, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap)
	if err != nil || len(buf) != 48 {
		t.Fatalf("fallback failed %v", err)
	}
	if len(fake.operations) != 2 || fake.operations[1] != srccopy {
		t.Fatal("no plain SRCCOPY fallback")
	}
}

func TestGDICaptureRetryReselectsBitmapAfterReadback(t *testing.T) {
	fake := &fakeGDICapture{t: t, readLines: []uintptr{0, 3}}
	buf, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap)
	if err != nil || len(buf) != 48 {
		t.Fatalf("readback retry failed %v", err)
	}
	if strings.Count(strings.Join(fake.events, ","), "selectCapture") != 2 {
		t.Fatal("retry did not reselect bitmap")
	}
}

func TestGDICaptureAcceptsRealBlackAndIgnoresStaleLastError(t *testing.T) {
	t.Run("black", func(t *testing.T) {
		fake := &fakeGDICapture{t: t, black: true}
		buf, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap)
		if err != nil || !bytes.Equal(buf, make([]byte, 48)) {
			t.Fatalf("legitimate black capture rejected %v", err)
		}
	})
	t.Run("blackWithFailedOptionalRetry", func(t *testing.T) {
		fake := &fakeGDICapture{t: t, black: true, copyFails: []bool{false, true}}
		buf, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap)
		if err != nil || len(buf) != 48 {
			t.Fatalf("valid black frame lost after retry failure %v", err)
		}
	})
	t.Run("staleLastError", func(t *testing.T) {
		fake := &fakeGDICapture{t: t, readErrors: []error{errors.New("stale error")}}
		if _, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap); err != nil {
			t.Fatal(err)
		}
	})
}

func TestGDICaptureFailedRestoreReleasesDCBeforeBitmap(t *testing.T) {
	fake := &fakeGDICapture{t: t, restoreFails: true}
	if _, err := captureGDIRegion(monitorRect{0, 0, 4, 3}, fake.call, fake.readBitmap); err == nil {
		t.Fatal("restore failure ignored")
	}
	if !strings.HasSuffix(strings.Join(fake.events, ","), "deleteDC,deleteBitmap,releaseDC") {
		t.Fatalf("unsafe failure cleanup %v", fake.events)
	}
}

func TestGDICaptureInvalidDimensionsDoNotAllocate(t *testing.T) {
	fake := &fakeGDICapture{t: t}
	if _, err := captureGDIRegion(monitorRect{}, fake.call, fake.readBitmap); err == nil {
		t.Fatal("empty capture accepted")
	}
	if len(fake.events) != 0 {
		t.Fatal("invalid dimensions allocated GDI handles")
	}
}
