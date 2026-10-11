package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image/jpeg"
	"math"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestGDIPerformanceRecordsCaptureAndActualEncodedDimensions(t *testing.T) {
	start := time.Now()
	p := newRemotePerformance(start)
	fake := &fakeGDICapture{t: t, splitColors: true}
	call := func(proc *windows.LazyProc, args ...uintptr) (uintptr, uintptr, error) {
		if proc == procBitBlt {
			time.Sleep(2 * time.Millisecond)
		}
		return fake.call(proc, args...)
	}
	frame, width, height, err := captureGDIJPEGRegionTimed(60, monitorRect{-32, 10, 0, 26}, 16, 8, call, fake.readBitmap, p)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := jpeg.DecodeConfig(bytes.NewReader(frame))
	if err != nil || encoded.Width != 16 || encoded.Height != 8 || width != 16 || height != 8 {
		t.Fatalf("timed capture changed encoded dimensions: returned %dx%d encoded %+v error %v", width, height, encoded, err)
	}
	w := p.snapshot(time.Now())
	if w.NativeW != 32 || w.NativeH != 16 || w.EncodedW != encoded.Width || w.EncodedH != encoded.Height {
		t.Fatalf("reported dimensions do not describe produced JPEG: %+v", w)
	}
	if w.Timings.GDICapture.Samples != 1 || w.Timings.GDICapture.MeanMS < 2 || w.Timings.JPEGEncode.Samples != 1 || !w.valid() {
		t.Fatalf("capture delay was lost or confused with JPEG encoding: %+v", w.Timings)
	}
	if w.FullFrames != 0 || w.GDIFrames != 0 {
		t.Fatal("capturing pixels falsely reported that a frame was sent")
	}
}

func TestGDIPerformanceIncludesFailedCaptureWithoutFalseEncode(t *testing.T) {
	p := newRemotePerformance(time.Now())
	fake := &fakeGDICapture{t: t, readLines: []uintptr{0, 0}}
	read := func(dc, bitmap uintptr, pixels []byte, info *bitmapInfoHeader) (uintptr, error) {
		time.Sleep(2 * time.Millisecond)
		return fake.readBitmap(dc, bitmap, pixels, info)
	}
	frame, _, _, err := captureGDIJPEGRegionTimed(60, monitorRect{0, 0, 4, 3}, 2, 2, fake.call, read, p)
	if err == nil || frame != nil || fake.reads != 2 {
		t.Fatalf("failed readback unexpectedly produced frame: %v reads=%d", err, fake.reads)
	}
	w := p.snapshot(time.Now())
	if w.Timings.GDICapture.Samples != 1 || w.Timings.GDICapture.MeanMS < 4 || w.Timings.JPEGEncode.Samples != 0 {
		t.Fatalf("failed capture stall was lost or reported as encoding: %+v", w.Timings)
	}
	if w.NativeW != 0 || w.EncodedW != 0 || w.FullFrames != 0 || !w.valid() {
		t.Fatalf("failed capture produced false frame metadata: %+v", w)
	}
}

func TestDXGIPerformanceResetsIdleAndIncludesFailedReadback(t *testing.T) {
	fake := newFakeDXGICapture(t,
		fakeDXGIFrame{present: 1, accumulated: 4},
		fakeDXGIFrame{mouse: 2},
		fakeDXGIFrame{present: 3, accumulated: 6, mapError: true},
	)
	defer runtime.KeepAlive(fake)
	// Simulate a stalled GPU copy with fake COM only. This gives a measurable
	// readback duration even on Windows clocks with coarse test-time resolution.
	fake.contextVT[47] = syscall.NewCallback(func(this, destination, source uintptr) uintptr {
		fake.copies++
		if destination != uintptr(unsafe.Pointer(&fake.staging)) || source != uintptr(unsafe.Pointer(&fake.texture)) {
			t.Error("copied incorrect fake texture resources")
		}
		time.Sleep(2 * time.Millisecond)
		return 0x80004005 // CopyResource returns void, so this value is ignored.
	})
	if _, _, _, _, err := fake.capturer.grabBGRA(); err != nil {
		t.Fatal(err)
	}
	if !fake.capturer.lastReadbackAttempt || fake.capturer.lastWait < 0 || fake.capturer.lastReadback < 2*time.Millisecond || fake.capturer.lastAccumulated != 4 {
		t.Fatalf("real desktop acquisition did not record timing: wait=%v readback=%v accumulated=%d", fake.capturer.lastWait, fake.capturer.lastReadback, fake.capturer.lastAccumulated)
	}
	if _, _, _, _, err := fake.capturer.grabBGRA(); !errors.Is(err, errNoNewFrame) {
		t.Fatalf("cursor-only acquisition was not idle: %v", err)
	}
	if fake.capturer.lastReadbackAttempt || fake.capturer.lastReadback != 0 || fake.capturer.lastAccumulated != 0 {
		t.Fatal("idle cursor acquisition inherited previous desktop readback measurements")
	}
	if _, _, _, _, err := fake.capturer.grabBGRA(); err == nil {
		t.Fatal("failed texture map unexpectedly produced desktop pixels")
	}
	if !fake.capturer.lastReadbackAttempt || fake.capturer.lastReadback < 2*time.Millisecond || fake.capturer.lastAccumulated != 6 {
		t.Fatalf("failed readback stall disappeared: readback=%v accumulated=%d", fake.capturer.lastReadback, fake.capturer.lastAccumulated)
	}
	if fake.maps != 2 || fake.unmaps != 1 || fake.frameReleases != 3 || fake.resourceReleases != 3 || fake.textureReleases != 2 {
		t.Fatalf("timing instrumentation changed failure cleanup: maps=%d unmaps=%d frames=%d resources=%d textures=%d", fake.maps, fake.unmaps, fake.frameReleases, fake.resourceReleases, fake.textureReleases)
	}
}

func TestRemoteInputPipePreservesMixedLegacyAndTimedBarriers(t *testing.T) {
	events := [][]byte{
		[]byte(`{"type":"mousemove","x":5,"y":8}`),
		[]byte(`{"type":"mousedown","button":"left","x":7,"y":9}`),
		[]byte(`{"type":"mousemove","x":10,"y":11}`),
		[]byte(`{"type":"mouseup","button":"left","x":10,"y":11}`),
		[]byte(`{"type":"keydown","key":"Shift"}`),
		[]byte(`{"type":"scroll","delta":-1}`),
		[]byte(`{"type":"keyup","key":"Shift"}`),
	}
	var pipe bytes.Buffer
	for index, raw := range events {
		tag, payload := byte('I'), raw
		if index%2 == 0 {
			var err error
			// A future clock on the final key release must not discard it.
			payload, err = buildRemoteTimedInput(raw, uint64(100+index))
			if err != nil {
				t.Fatal(err)
			}
			tag = remoteTimedInputTag
		}
		if err := writePipeMsg(&pipe, tag, payload); err != nil {
			t.Fatal(err)
		}
	}
	for index, want := range events {
		tag, payload, err := readPipeMsg(&pipe)
		if err != nil {
			t.Fatal(err)
		}
		if tag == remoteTimedInputTag {
			var measured bool
			payload, _, measured, err = decodeRemoteTimedInput(payload, 105)
			if err != nil || (index == len(events)-1 && measured) {
				t.Fatalf("future timing affected key release: measured=%v error=%v", measured, err)
			}
		} else if tag != 'I' {
			t.Fatalf("unexpected input tag %q", tag)
		}
		if !bytes.Equal(payload, want) {
			t.Fatalf("input %d changed, reordered or disappeared: got %q want %q", index, payload, want)
		}
	}
	if pipe.Len() != 0 {
		t.Fatal("input framing left extra bytes after releases")
	}
}

func TestRemoteTimedInputPipeRejectsInvalidSizeBeforeReadingBody(t *testing.T) {
	for _, length := range []uint32{0, 1, remoteTimedInputHeaderSize, remoteTimedInputHeaderSize + remoteInputMaxBytes + 1, math.MaxUint32} {
		header := make([]byte, pipeHeaderSize)
		header[0] = remoteTimedInputTag
		binary.LittleEndian.PutUint32(header[1:], length)
		_, payload, err := readPipeMsg(bytes.NewReader(header))
		if err == nil || payload != nil || !strings.Contains(err.Error(), "timed") {
			t.Fatalf("length %d reached body read instead of size guard: payload=%d error=%v", length, len(payload), err)
		}
	}
}
