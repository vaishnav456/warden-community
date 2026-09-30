package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The single call seam keeps real capture and its failure/cleanup tests on
// the same Win32 operation sequence.
type gdiCaptureCall func(*windows.LazyProc, ...uintptr) (uintptr, uintptr, error)
type gdiBitmapRead func(uintptr, uintptr, []byte, *bitmapInfoHeader) (uintptr, error)

func systemGDICaptureCall(proc *windows.LazyProc, args ...uintptr) (uintptr, uintptr, error) {
	return proc.Call(args...)
}

// Keep Go pointers typed until the direct syscall boundary. Routing buffer or
// header addresses as uintptr through a Go callback could lose stack/pointer
// lifetime tracking before Windows reads them.
func systemGDIBitmapRead(dc, bitmap uintptr, buf []byte, info *bitmapInfoHeader) (uintptr, error) {
	lines, _, err := procGetDIBits.Call(dc, bitmap, 0, uintptr(-info.biHeight),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(info)), 0)
	return lines, err
}

func captureGDIRegion(region monitorRect, call gdiCaptureCall, readBitmap gdiBitmapRead) ([]byte, error) {
	// GetDC/ReleaseDC and the GDI batch flushed below belong to one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w, h := region.width(), region.height()
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid capture dimensions %dx%d", w, h)
	}
	hDC, _, err := call(procGetDC, 0)
	if hDC == 0 {
		return nil, fmt.Errorf("GetDC failed: %v", err)
	}
	var hMemDC, hBMP, oldBitmap uintptr
	selected := false
	defer func() {
		if selected {
			restored, _, _ := call(procSelectObject, hMemDC, oldBitmap)
			if restored != 0 && restored != ^uintptr(0) {
				selected = false
			}
		}
		// If restoration fails, destroy the memory DC first to release its
		// selection, rather than attempting to delete a selected bitmap.
		if selected && hMemDC != 0 {
			call(procDeleteDC, hMemDC)
			hMemDC = 0
		}
		if hBMP != 0 {
			call(procDeleteObject, hBMP)
		}
		if hMemDC != 0 {
			call(procDeleteDC, hMemDC)
		}
		call(procReleaseDC, 0, hDC)
	}()
	hMemDC, _, err = call(procCreateCompatibleDC, hDC)
	if hMemDC == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed: %v", err)
	}
	hBMP, _, err = call(procCreateCompatibleBitmap, hDC, uintptr(w), uintptr(h))
	if hBMP == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed: %v", err)
	}
	oldBitmap, _, err = call(procSelectObject, hMemDC, hBMP)
	if oldBitmap == 0 || oldBitmap == ^uintptr(0) {
		return nil, fmt.Errorf("SelectObject bitmap failed: %v", err)
	}
	selected = true

	capture := func(operation uintptr) ([]byte, error) {
		if !selected {
			previous, _, selectErr := call(procSelectObject, hMemDC, hBMP)
			if previous == 0 || previous == ^uintptr(0) {
				return nil, fmt.Errorf("SelectObject bitmap failed: %v", selectErr)
			}
			selected = true
		}
		copied, _, copyErr := call(procBitBlt, hMemDC, 0, 0, uintptr(w), uintptr(h),
			hDC, uintptr(region.Left), uintptr(region.Top), operation)
		if copied == 0 {
			return nil, fmt.Errorf("BitBlt failed: %v", copyErr)
		}
		flushed, _, flushErr := call(procGdiFlush)
		if flushed == 0 {
			return nil, fmt.Errorf("GdiFlush failed: %v", flushErr)
		}
		// GetDIBits requires the bitmap to be deselected from every DC.
		restored, _, restoreErr := call(procSelectObject, hMemDC, oldBitmap)
		if restored == 0 || restored == ^uintptr(0) {
			return nil, fmt.Errorf("restore capture bitmap failed: %v", restoreErr)
		}
		selected = false
		bi := bitmapInfoHeader{biSize: 40, biWidth: int32(w), biHeight: -int32(h), biPlanes: 1, biBitCount: 32}
		buf := make([]byte, w*h*4)
		lines, readErr := readBitmap(hDC, hBMP, buf, &bi)
		if lines != uintptr(h) {
			return nil, fmt.Errorf("GetDIBits copied %d of %d scanlines: %v", lines, h, readErr)
		}
		return buf, nil
	}
	first, firstErr := capture(srccopy | captureBlt)
	if firstErr == nil && !bufAppearsBlack(first, w, h) {
		return first, nil
	}
	// Some display drivers reject CAPTUREBLT or omit the secure/layered
	// desktop. Retry ordinary SRCCOPY, with the same validated readback.
	fallback, fallbackErr := capture(srccopy)
	if fallbackErr == nil {
		return fallback, nil
	}
	if firstErr == nil {
		// A valid black image is allowed. A failed optional retry must not
		// convert legitimate black content into an error or desktop switch.
		return first, nil
	}
	return nil, fmt.Errorf("capture with CAPTUREBLT failed (%v); SRCCOPY failed (%v)", firstErr, fallbackErr)
}
