package main

// remote_pipe.go — tagged length-prefixed framing over a Windows named pipe.
//
// Go port of remote_pipe.py: used for local IPC between the SYSTEM-side
// relay session (remote.go, owns the outbound WSS connection) and the
// interactive-session helper (remote_helper.go, launched via
// launchInteractiveHelper into whichever session owns the console — SYSTEM's
// own session 0 has no real desktop to capture/send input into). Two
// one-way pipes are used, each carrying frames of:
//
//	1 byte tag | 4 bytes little-endian length | payload
//
// Tags:
//
//	'S'  screen size, payload = utf-8 "WIDTHxHEIGHT"   (helper -> service, once)
//	'F'  full JPEG frame, payload = jpeg bytes          (helper -> service)
//	'P'  partial JPEG frame update, payload = 8-byte header (x,y,w,h, each a
//	     little-endian uint16, in native/canvas pixel coordinates) followed
//	     by jpeg bytes for just that sub-rectangle — see buildPartialFramePayload
//	     and remote_helper.go's capture loop           (helper -> service)
//	'C'  clipboard text, payload = utf-8 text            (helper -> service)
//	'D'  foreground Explorer directory, utf-8 path       (helper -> service)
//	'X'  input desktop changed; restart on other desktop  (helper -> service)
//	'M'  JSON monitor inventory                           (helper -> service)
//	'L'  log line, payload = utf-8 text                   (helper -> service)
//	'I'  input event, payload = utf-8 JSON               (service -> helper)

import (
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pipeHeaderSize = 5 // 1-byte tag + 4-byte little-endian length

// pipeFile adapts a raw Windows pipe Handle to io.Reader/io.Writer via
// ReadFile/WriteFile, so the same framing code works for both the server
// side (remote.go) and the client side (remote_helper.go).
type pipeFile struct {
	h windows.Handle
}

func (p pipeFile) Read(buf []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(p.h, buf, &n, nil)
	if err != nil {
		return int(n), err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (p pipeFile) Write(buf []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(p.h, buf, &n, nil)
	return int(n), err
}

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("pipe closed while reading")
		}
		return nil, err
	}
	return buf, nil
}

// buildPartialFramePayload assembles a 'P' pipe payload: x,y,w,h (each a
// little-endian uint16, in native/canvas pixel coordinates — capped at
// 65535, which covers any real display resolution) followed by the JPEG
// bytes for that sub-rectangle. The same encoding is reused verbatim as the
// WS binary payload sent to the browser (see remote.go's pump goroutine),
// just with a 1-byte frame-type marker prepended there.
func buildPartialFramePayload(x, y, w, h int, jpg []byte) []byte {
	out := make([]byte, 8+len(jpg))
	binary.LittleEndian.PutUint16(out[0:], uint16(x))
	binary.LittleEndian.PutUint16(out[2:], uint16(y))
	binary.LittleEndian.PutUint16(out[4:], uint16(w))
	binary.LittleEndian.PutUint16(out[6:], uint16(h))
	copy(out[8:], jpg)
	return out
}

func writePipeMsg(w io.Writer, tag byte, payload []byte) error {
	header := make([]byte, pipeHeaderSize)
	header[0] = tag
	binary.LittleEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readPipeMsg returns (tag, payload). Returns an error (io.EOF or otherwise)
// when the pipe is closed.
func readPipeMsg(r io.Reader) (byte, []byte, error) {
	header, err := readExact(r, pipeHeaderSize)
	if err != nil {
		return 0, nil, err
	}
	tag := header[0]
	length := binary.LittleEndian.Uint32(header[1:])
	if length == 0 {
		return tag, nil, nil
	}
	// The pipe ACL deliberately grants the active console user write access
	// (it's the whole point — the interactive helper runs in that user's
	// session, not SYSTEM's). That means `length` is attacker-controlled by
	// whichever process manages to connect as that user first (a race
	// against the real helper). Without a cap, a length near 4 GiB would
	// make readExact allocate that much before reading a single payload
	// byte, OOMing or hanging the SYSTEM-side relay process. maxPipeFrame
	// is comfortably above any real JPEG frame this agent ever sends.
	if length > maxPipeFrame {
		return 0, nil, fmt.Errorf("pipe frame length %d exceeds max %d", length, maxPipeFrame)
	}
	payload, err := readExact(r, int(length))
	if err != nil {
		return 0, nil, err
	}
	return tag, payload, nil
}

const pipeBufferSize = 1 << 20 // 1 MiB — comfortably larger than a single JPEG frame
const maxPipeFrame = 16 << 20  // 16 MiB — hard cap on any single frame readPipeMsg will allocate for

// createPipeServer creates a named pipe server end with the given access
// direction (PIPE_ACCESS_INBOUND / PIPE_ACCESS_OUTBOUND) and SDDL security
// descriptor.
func createPipeServer(name string, access uint32, sddl string) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return 0, fmt.Errorf("SecurityDescriptorFromString: %w", err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateNamedPipe(
		namePtr,
		access,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		1, // max instances
		pipeBufferSize, pipeBufferSize,
		0, // default timeout
		sa,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateNamedPipe: %w", err)
	}
	return h, nil
}

// connectNamedPipeTolerant calls ConnectNamedPipe, tolerating the
// client-already-connected race: if the client connects between
// CreateNamedPipe and this call, Windows reports it as the
// ERROR_PIPE_CONNECTED "error" rather than success — that is not a failure.
func connectNamedPipeTolerant(h windows.Handle) error {
	err := windows.ConnectNamedPipe(h, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return err
	}
	return nil
}
