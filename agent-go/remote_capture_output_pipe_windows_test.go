//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests transport only synthetic bytes in their own randomly named local
// pipe. They do not connect to the helper, desktop, service, input or network.
type captureTestPipe struct {
	reader, writer         windows.Handle
	readerOnce, writerOnce sync.Once
	closeErrors            chan error
}

func newCaptureTestPipe(t *testing.T, buffer uint32, defaultBuffer bool) *captureTestPipe {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := `\\.\pipe\WardenCaptureBufferTest-` + hex.EncodeToString(nonce[:])
	sddl := "D:P(A;;GA;;;SY)(A;;GRGW;;;" + user.User.Sid.String() + ")"
	access := uint32(windows.PIPE_ACCESS_INBOUND | windows.FILE_FLAG_FIRST_PIPE_INSTANCE)
	var reader windows.Handle
	if defaultBuffer {
		reader, err = createPipeServer(name, access, sddl)
	} else {
		reader, err = createPipeServerWithBuffer(name, access, sddl, buffer)
	}
	if err != nil {
		t.Fatal(err)
	}
	p := &captureTestPipe{reader: reader, closeErrors: make(chan error, 2)}
	t.Cleanup(func() {
		p.close()
		for {
			select {
			case err := <-p.closeErrors:
				t.Errorf("owned pipe handle cleanup: %v", err)
			default:
				return
			}
		}
	})
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	p.writer, err = windows.CreateFile(ptr, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectNamedPipeTolerant(p.reader); err != nil {
		t.Fatal(err)
	}
	// Cancel and close only these two handles if an assertion/read/write stalls.
	watchdog := time.AfterFunc(5*time.Second, p.close)
	t.Cleanup(func() { watchdog.Stop() })
	return p
}

func (p *captureTestPipe) closeReader() {
	p.readerOnce.Do(func() {
		_ = windows.CancelIoEx(p.reader, nil)
		if err := windows.CloseHandle(p.reader); err != nil {
			p.closeErrors <- err
		}
	})
}
func (p *captureTestPipe) closeWriter() {
	p.writerOnce.Do(func() {
		if p.writer == 0 {
			return
		}
		_ = windows.CancelIoEx(p.writer, nil)
		if err := windows.CloseHandle(p.writer); err != nil {
			p.closeErrors <- err
		}
	})
}
func (p *captureTestPipe) close() { p.closeReader(); p.closeWriter() }

func capturePipeResult(t *testing.T, p *captureTestPipe, done <-chan error) error {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		p.close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned pipe goroutine did not exit after cancellation")
		}
		t.Fatal("owned pipe operation exceeded watchdog")
		return nil
	}
}

func capturePipePending(h windows.Handle) (uint32, error) {
	var available uint32
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")
	ok, _, err := proc.Call(uintptr(h), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
	if ok == 0 {
		return 0, err
	}
	return available, nil
}

func awaitCapturePipeBytes(t *testing.T, p *captureTestPipe, done <-chan error) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		available, err := capturePipePending(p.reader)
		if err != nil {
			t.Fatal(err)
		}
		if available >= captureOutputPipeBufferSize {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("oversized write completed before consumer read: %v", err)
		case <-deadline.C:
			t.Fatal("oversized write did not fill its owned output buffer")
		case <-tick.C:
		}
	}
}

func capturePipeSynthetic(size, seed int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte((i*37 + seed) % 251)
	}
	return out
}

type capturePipeChunkReader struct{ io.Reader }

func (r capturePipeChunkReader) Read(b []byte) (int, error) {
	if len(b) > 4093 {
		b = b[:4093]
	}
	return r.Reader.Read(b)
}

func TestCaptureOutputPipeUsesExplicitBufferAndRetainsDefault(t *testing.T) {
	if captureOutputPipeBufferSize != 64<<10 || pipeBufferSize != 1<<20 {
		t.Fatal("capture or default pipe quota changed")
	}
	for _, tc := range []struct {
		name          string
		buffer        uint32
		defaultBuffer bool
	}{
		{"capture", captureOutputPipeBufferSize, false},
		{"input-and-consent-default", pipeBufferSize, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newCaptureTestPipe(t, tc.buffer, tc.defaultBuffer)
			var flags, inputBuffer, instances uint32
			if err := windows.GetNamedPipeInfo(p.reader, &flags, nil, &inputBuffer, &instances); err != nil {
				t.Fatal(err)
			}
			if inputBuffer != tc.buffer || instances != 1 || flags&windows.PIPE_TYPE_MESSAGE != 0 {
				t.Fatalf("wrong pipe buffer or framing: input=%d want=%d flags=%d instances=%d", inputBuffer, tc.buffer, flags, instances)
			}
		})
	}
}

func TestCaptureOutputPipePreservesLargeFullPartialFullFIFO(t *testing.T) {
	p := newCaptureTestPipe(t, captureOutputPipeBufferSize, false)
	messages := []struct {
		tag     byte
		payload []byte
	}{
		{'F', capturePipeSynthetic((257<<10)+17, 1)},
		{'P', buildPartialFramePayload(3, 5, 320, 240, capturePipeSynthetic((129<<10)+3, 2))},
		{'F', capturePipeSynthetic((91<<10)+11, 3)},
	}
	written := make(chan error, 1)
	read := make(chan error, 1)
	go func() {
		for _, m := range messages {
			if err := writePipeMsg(pipeFile{p.writer}, m.tag, m.payload); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	go func() {
		// Force reads to cross both the five-byte frame header and the 64 KiB
		// kernel-buffer boundary without changing the production readExact code.
		r := capturePipeChunkReader{pipeFile{p.reader}}
		for sequence, want := range messages {
			tag, payload, err := readPipeMsg(r)
			if err != nil {
				read <- err
				return
			}
			if tag != want.tag || !bytes.Equal(payload, want.payload) {
				read <- fmt.Errorf("frame %d lost FIFO, tag or bytes: got=%q/%d want=%q/%d", sequence, tag, len(payload), want.tag, len(want.payload))
				return
			}
		}
		read <- nil
	}()
	if err := capturePipeResult(t, p, read); err != nil {
		t.Fatal(err)
	}
	if err := capturePipeResult(t, p, written); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureOutputPipeBackpressureWaitsForConsumerWithoutDroppingFrame(t *testing.T) {
	p := newCaptureTestPipe(t, captureOutputPipeBufferSize, false)
	payload := capturePipeSynthetic(4*int(captureOutputPipeBufferSize)+19, 4)
	done := make(chan error, 1)
	go func() { done <- writePipeMsg(pipeFile{p.writer}, 'F', payload) }()
	awaitCapturePipeBytes(t, p, done)
	select {
	case err := <-done:
		t.Fatalf("large frame bypassed output backpressure: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	read := make(chan error, 1)
	go func() {
		tag, got, err := readPipeMsg(capturePipeChunkReader{pipeFile{p.reader}})
		if err == nil && (tag != 'F' || !bytes.Equal(got, payload)) {
			err = fmt.Errorf("blocked full frame changed")
		}
		read <- err
	}()
	if err := capturePipeResult(t, p, read); err != nil {
		t.Fatal(err)
	}
	if err := capturePipeResult(t, p, done); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureOutputPipeDisconnectReleasesBlockedWriter(t *testing.T) {
	p := newCaptureTestPipe(t, captureOutputPipeBufferSize, false)
	done := make(chan error, 1)
	go func() {
		done <- writePipeMsg(pipeFile{p.writer}, 'F', capturePipeSynthetic(4*int(captureOutputPipeBufferSize), 5))
	}()
	awaitCapturePipeBytes(t, p, done)
	p.closeReader()
	if err := capturePipeResult(t, p, done); err == nil {
		t.Fatal("disconnected output pipe falsely completed blocked frame")
	}
}

func TestCaptureOutputPipeTruncatedLargeFrameReturnsError(t *testing.T) {
	p := newCaptureTestPipe(t, captureOutputPipeBufferSize, false)
	done := make(chan error, 1)
	go func() {
		header := make([]byte, pipeHeaderSize)
		header[0] = 'P'
		binary.LittleEndian.PutUint32(header[1:], 2*captureOutputPipeBufferSize)
		w := pipeFile{p.writer}
		if _, err := w.Write(header); err != nil {
			done <- err
			return
		}
		_, err := w.Write(capturePipeSynthetic(17, 6))
		p.closeWriter()
		done <- err
	}()
	read := make(chan error, 1)
	go func() {
		_, payload, err := readPipeMsg(pipeFile{p.reader})
		if err == nil || payload != nil {
			read <- fmt.Errorf("truncated frame returned payload=%d error=%v", len(payload), err)
			return
		}
		read <- nil
	}()
	if err := capturePipeResult(t, p, read); err != nil {
		t.Fatal(err)
	}
	if err := capturePipeResult(t, p, done); err != nil {
		t.Fatal(err)
	}
}
