package main

// dxgi_capture.go — screen capture via the Desktop Duplication API
// (IDXGIOutputDuplication), used in preference to the plain GDI BitBlt path
// in remote.go/grabJPEGRegion() when available.
//
// Why this exists: on real hardware with a GPU-composited desktop (DWM using
// a hardware flip-model swapchain — the normal case on any modern Windows 10/
// 11 machine), GetDC(0)+BitBlt frequently cannot see the final composited
// frame at all and reads back solid black, because that frame lives in a GPU
// surface BitBlt has no access to. This is exactly why every serious
// screen-capture tool (OBS, etc.) moved off GDI BitBlt years ago in favor of
// Desktop Duplication, which captures the real composited output directly
// from the GPU. Confirmed live: a real (non-VM) test machine, screen awake,
// produced a continuous stream of genuinely all-black frames via the GDI
// path even after every earlier GDI-side fix in this file/remote_helper.go.
//
// golang.org/x/sys/windows has no D3D11/DXGI bindings, and this project
// builds as pure Go with no cgo (see build-service/Dockerfile — the whole
// point of that setup is cross-compiling from a plain Linux container), so
// these COM interfaces are called directly through their vtables via
// syscall.SyscallN, the same technique go-ole and other pure-Go COM bindings
// use. The vtable indices below are the fixed, ABI-stable method order from
// the Windows SDK's d3d11.h / dxgi.h / dxgi1_2.h — once a COM interface ships
// its vtable layout can never change, only have new interfaces added.
//
// Desktop Duplication is explicitly documented by Microsoft to NOT work on
// the secure desktop (Winlogon/UAC) — newDXGICapturer() simply fails there,
// which the capture loop in remote_helper.go treats like any other DXGI
// failure: fall back to the existing (already fixed) GDI path for that
// helper's lifetime. Only the primary output (index 0) is attempted; a
// non-primary monitor selection always uses the GDI path.

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	d3d11DLL              = windows.NewLazySystemDLL("d3d11.dll")
	procD3D11CreateDevice = d3d11DLL.NewProc("D3D11CreateDevice")
)

// IIDs, byte-for-byte from the Windows SDK headers — stable across every
// Windows version since each interface shipped.
var (
	iidIDXGIDevice     = windows.GUID{Data1: 0x54ec77fa, Data2: 0x1377, Data3: 0x44e6, Data4: [8]byte{0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c}}
	iidIDXGIOutput1    = windows.GUID{Data1: 0x00cddea8, Data2: 0x939b, Data3: 0x4b83, Data4: [8]byte{0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc}}
	iidID3D11Texture2D = windows.GUID{Data1: 0x6f15aaf2, Data2: 0xd208, Data3: 0x4e89, Data4: [8]byte{0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}}
)

const (
	d3dDriverTypeHardware = 1
	d3d11SDKVersion       = 7
	dxgiFormatB8G8R8A8    = 87
	d3d11UsageStaging     = 3
	d3d11CPUAccessRead    = 0x20000
	d3d11MapRead          = 1

	hrDXGIWaitTimeout = 0x887A0027
	hrDXGIAccessLost  = 0x887A0026
)

var (
	errNoNewFrame = errors.New("dxgi: no new frame since last capture")
	errAccessLost = errors.New("dxgi: access lost (desktop/mode changed)")
)

// ── Raw COM plumbing ─────────────────────────────────────────────────────────

// comCall invokes the method at vtable index `idx` on the COM object `this`,
// returning the raw HRESULT. Every COM interface starts with the IUnknown
// triad (0=QueryInterface, 1=AddRef, 2=Release); interface-specific methods
// follow starting at index 3 (or later, for interfaces with intermediate
// base interfaces like IDXGIObject).
func comCall(this unsafe.Pointer, idx int, args ...uintptr) (int32, error) {
	vtbl := *(*uintptr)(this)
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	full := make([]uintptr, 0, len(args)+1)
	full = append(full, uintptr(this))
	full = append(full, args...)
	r1, _, _ := syscall.SyscallN(fn, full...)
	hr := int32(r1)
	if hr < 0 {
		return hr, fmt.Errorf("HRESULT 0x%08X", uint32(hr))
	}
	return hr, nil
}

// D3D11 methods such as CopyResource and Unmap return void, not HRESULT.
// Their return register is unspecified and must never trigger a fallback.
func comCallVoid(this unsafe.Pointer, idx int, args ...uintptr) {
	vtbl := *(*uintptr)(this)
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	full := append([]uintptr{uintptr(this)}, args...)
	syscall.SyscallN(fn, full...)
}

func comQueryInterface(this unsafe.Pointer, iid *windows.GUID) (unsafe.Pointer, error) {
	var out unsafe.Pointer
	if _, err := comCall(this, 0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out))); err != nil {
		return nil, err
	}
	return out, nil
}

func comRelease(this unsafe.Pointer) {
	if this != nil {
		comCall(this, 2)
	}
}

// ── D3D11 / DXGI struct layouts ──────────────────────────────────────────────
// Field order/sizes match the C structs exactly; Go's default alignment for
// these (all 4-byte-or-larger fields, no packing pragmas in the originals)
// matches the C layout without extra tags.

type dxgiSampleDesc struct {
	Count   uint32
	Quality uint32
}

type d3d11Texture2DDesc struct {
	Width          uint32
	Height         uint32
	MipLevels      uint32
	ArraySize      uint32
	Format         uint32
	SampleDesc     dxgiSampleDesc
	Usage          uint32
	BindFlags      uint32
	CPUAccessFlags uint32
	MiscFlags      uint32
}

type d3d11MappedSubresource struct {
	PData      uintptr
	RowPitch   uint32
	DepthPitch uint32
}

type dxgiRect struct {
	Left, Top, Right, Bottom int32
}

type dxgiOutputDesc struct {
	DeviceName         [32]uint16
	DesktopCoordinates dxgiRect
	AttachedToDesktop  int32
	Rotation           uint32
	Monitor            uintptr
}

type dxgiOutduplPointerPosition struct {
	Position struct{ X, Y int32 }
	Visible  int32
}

type dxgiOutduplFrameInfo struct {
	LastPresentTime           int64
	LastMouseUpdateTime       int64
	AccumulatedFrames         uint32
	RectsCoalesced            int32
	ProtectedContentMaskedOut int32
	PointerPosition           dxgiOutduplPointerPosition
	TotalMetadataBufferSize   uint32
	PointerShapeBufferSize    uint32
}

type dxgiMoveRect struct {
	SourcePoint     struct{ X, Y int32 }
	DestinationRect dxgiRect
}

// ── Capturer ──────────────────────────────────────────────────────────────────

type dxgiCapturer struct {
	device, context, dupl, staging unsafe.Pointer
	width, height                  int
	left, top                      int32
}

// newDXGICapturer sets up a Desktop Duplication session for the given
// zero-based output (monitor) index on the current desktop. Fails (by
// design, per Microsoft's own documentation) when called from the secure
// desktop — callers should treat any error here as "use GDI instead for
// this helper session," not retry in a loop.
func newDXGICapturer(outputIndex int) (cap *dxgiCapturer, err error) {
	var device, context unsafe.Pointer
	r1, _, _ := procD3D11CreateDevice.Call(
		0,                     // pAdapter: default
		d3dDriverTypeHardware, // DriverType
		0,                     // Software
		0,                     // Flags
		0, 0,                  // pFeatureLevels, count: let the runtime pick
		d3d11SDKVersion,
		uintptr(unsafe.Pointer(&device)),
		0, // pFeatureLevel out: not needed
		uintptr(unsafe.Pointer(&context)),
	)
	if hr := int32(r1); hr < 0 {
		return nil, fmt.Errorf("D3D11CreateDevice: HRESULT 0x%08X", uint32(hr))
	}
	defer func() {
		if err != nil {
			comRelease(device)
			comRelease(context)
		}
	}()

	dxgiDevice, err := comQueryInterface(device, &iidIDXGIDevice)
	if err != nil {
		return nil, fmt.Errorf("QueryInterface(IDXGIDevice): %w", err)
	}
	defer comRelease(dxgiDevice)

	var adapter unsafe.Pointer
	if _, err = comCall(dxgiDevice, 7, uintptr(unsafe.Pointer(&adapter))); err != nil { // IDXGIDevice::GetAdapter
		return nil, fmt.Errorf("GetAdapter: %w", err)
	}
	defer comRelease(adapter)

	var output unsafe.Pointer
	if _, err = comCall(adapter, 7, uintptr(outputIndex), uintptr(unsafe.Pointer(&output))); err != nil { // IDXGIAdapter::EnumOutputs
		return nil, fmt.Errorf("EnumOutputs(%d): %w", outputIndex, err)
	}
	defer comRelease(output)

	var desc dxgiOutputDesc
	if _, err = comCall(output, 7, uintptr(unsafe.Pointer(&desc))); err != nil { // IDXGIOutput::GetDesc
		return nil, fmt.Errorf("IDXGIOutput.GetDesc: %w", err)
	}
	width := int(desc.DesktopCoordinates.Right - desc.DesktopCoordinates.Left)
	height := int(desc.DesktopCoordinates.Bottom - desc.DesktopCoordinates.Top)
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("IDXGIOutput.GetDesc reported empty bounds (%dx%d)", width, height)
	}

	output1, err := comQueryInterface(output, &iidIDXGIOutput1)
	if err != nil {
		return nil, fmt.Errorf("QueryInterface(IDXGIOutput1): %w", err)
	}
	defer comRelease(output1)

	var dupl unsafe.Pointer
	if _, err = comCall(output1, 22, uintptr(device), uintptr(unsafe.Pointer(&dupl))); err != nil { // IDXGIOutput1::DuplicateOutput
		return nil, fmt.Errorf("DuplicateOutput: %w", err)
	}
	defer func() {
		if err != nil {
			comRelease(dupl)
		}
	}()

	stagingDesc := d3d11Texture2DDesc{
		Width: uint32(width), Height: uint32(height),
		MipLevels: 1, ArraySize: 1,
		Format:         dxgiFormatB8G8R8A8,
		SampleDesc:     dxgiSampleDesc{Count: 1, Quality: 0},
		Usage:          d3d11UsageStaging,
		CPUAccessFlags: d3d11CPUAccessRead,
	}
	var staging unsafe.Pointer
	if _, err = comCall(device, 5, uintptr(unsafe.Pointer(&stagingDesc)), 0, uintptr(unsafe.Pointer(&staging))); err != nil { // ID3D11Device::CreateTexture2D
		return nil, fmt.Errorf("CreateTexture2D(staging): %w", err)
	}

	return &dxgiCapturer{
		device: device, context: context, dupl: dupl, staging: staging,
		width: width, height: height,
		left: desc.DesktopCoordinates.Left, top: desc.DesktopCoordinates.Top,
	}, nil
}

// grabBGRA returns one captured frame as a raw top-down BGRA buffer, plus the
// list of regions that actually changed since the previous frame (used to
// send partial updates instead of re-encoding the whole screen — see
// remote_helper.go's capture loop). An empty (nil) dirty list with a nil
// error means DXGI signalled a new frame but reported no dirty rects at all
// — this happens for cursor-only updates with no desktop image change, and
// should be treated like errNoNewFrame by the caller.
//
// Returns errNoNewFrame if nothing changed on screen since the last call
// (not a failure — Desktop Duplication only signals on actual screen
// changes), or errAccessLost if the desktop/display mode changed and this
// capturer must be closed and recreated.
func (c *dxgiCapturer) grabBGRA() (buf []byte, w, h int, dirty []dxgiRect, err error) {
	var frameInfo dxgiOutduplFrameInfo
	var resource unsafe.Pointer
	hr, aErr := comCall(c.dupl, 8, 500, uintptr(unsafe.Pointer(&frameInfo)), uintptr(unsafe.Pointer(&resource))) // AcquireNextFrame
	if aErr != nil {
		switch uint32(hr) {
		case hrDXGIWaitTimeout:
			return nil, 0, 0, nil, errNoNewFrame
		case hrDXGIAccessLost:
			return nil, 0, 0, nil, errAccessLost
		}
		return nil, 0, 0, nil, fmt.Errorf("AcquireNextFrame: %w", aErr)
	}
	defer func() {
		comRelease(resource)
		comCall(c.dupl, 14) // ReleaseFrame
	}()

	// Must be read while this frame is still acquired (before ReleaseFrame).
	dirty, dirtyErr := c.getDirtyRects(256)
	moves, moveErr := c.getMoveRects(256)
	if dirtyErr != nil || moveErr != nil {
		// Non-fatal: fall back to treating the whole frame as dirty rather
		// than failing the capture outright (e.g. a very fragmented change
		// pattern exceeding the 256-rect buffer — full-frame is the right
		// answer for that case anyway, not worth a bigger buffer/retry).
		dirty = nil
	} else {
		dirty = captureUpdateRects(dirty, moves)
	}

	tex, qErr := comQueryInterface(resource, &iidID3D11Texture2D)
	if qErr != nil {
		return nil, 0, 0, nil, fmt.Errorf("QueryInterface(ID3D11Texture2D): %w", qErr)
	}
	defer comRelease(tex)

	comCallVoid(c.context, 47, uintptr(c.staging), uintptr(tex)) // ID3D11DeviceContext::CopyResource

	var mapped d3d11MappedSubresource
	if _, mErr := comCall(c.context, 14, uintptr(c.staging), 0, d3d11MapRead, 0, uintptr(unsafe.Pointer(&mapped))); mErr != nil { // ID3D11DeviceContext::Map
		return nil, 0, 0, nil, fmt.Errorf("Map: %w", mErr)
	}
	defer comCallVoid(c.context, 15, uintptr(c.staging), 0) // Unmap

	rowBytes := c.width * 4
	out := make([]byte, rowBytes*c.height)
	for y := 0; y < c.height; y++ {
		src := unsafe.Slice((*byte)(unsafe.Pointer(mapped.PData+uintptr(y)*uintptr(mapped.RowPitch))), rowBytes)
		copy(out[y*rowBytes:(y+1)*rowBytes], src)
	}
	return out, c.width, c.height, dirty, nil
}

// getMoveRects returns regions relocated in the currently-acquired
// frame. Must be called between AcquireNextFrame and ReleaseFrame.
func (c *dxgiCapturer) getMoveRects(maxRects int) ([]dxgiMoveRect, error) {
	buf := make([]dxgiMoveRect, maxRects)
	var required uint32
	_, err := comCall(c.dupl, 10, // IDXGIOutputDuplication::GetFrameMoveRects
		uintptr(maxRects)*unsafe.Sizeof(dxgiMoveRect{}),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&required)))
	if err != nil {
		return nil, err
	}
	count := int(required) / int(unsafe.Sizeof(dxgiMoveRect{}))
	if count > maxRects {
		return nil, fmt.Errorf("move rectangle metadata exceeds buffer")
	}
	return buf[:count], nil
}

// getDirtyRects returns the regions changed in the currently-acquired frame.
func (c *dxgiCapturer) getDirtyRects(maxRects int) ([]dxgiRect, error) {
	rectSize := int(unsafe.Sizeof(dxgiRect{}))
	buf := make([]dxgiRect, maxRects)
	var required uint32
	hr, err := comCall(c.dupl, 9, // IDXGIOutputDuplication::GetFrameDirtyRects
		uintptr(maxRects*rectSize),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&required)),
	)
	if err != nil {
		return nil, fmt.Errorf("HRESULT 0x%08X", uint32(hr))
	}
	count := int(required) / rectSize
	if count > maxRects {
		count = maxRects
	}
	return buf[:count], nil
}

// unionDirtyRects returns the bounding box covering every rect, clamped to
// [0,maxW)x[0,maxH). ok is false if rects is empty or the union is degenerate
// (zero width or height) — the caller should treat that like "nothing to
// send this cycle" rather than send an empty crop.
func unionDirtyRects(rects []dxgiRect, maxW, maxH int) (x, y, w, h int, ok bool) {
	if len(rects) == 0 {
		return 0, 0, 0, 0, false
	}
	minX, minY := rects[0].Left, rects[0].Top
	maxX, maxY := rects[0].Right, rects[0].Bottom
	for _, r := range rects[1:] {
		if r.Left < minX {
			minX = r.Left
		}
		if r.Top < minY {
			minY = r.Top
		}
		if r.Right > maxX {
			maxX = r.Right
		}
		if r.Bottom > maxY {
			maxY = r.Bottom
		}
	}
	if minX < 0 {
		minX = 0
	}
	if minY < 0 {
		minY = 0
	}
	if int(maxX) > maxW {
		maxX = int32(maxW)
	}
	if int(maxY) > maxH {
		maxY = int32(maxH)
	}
	if maxX <= minX || maxY <= minY {
		return 0, 0, 0, 0, false
	}
	return int(minX), int(minY), int(maxX - minX), int(maxY - minY), true
}

// cropBGRA extracts the sub-rectangle (x,y,w,h) from a full-size top-down
// BGRA buffer of dimensions fullW x fullH.
func cropBGRA(buf []byte, fullW, x, y, w, h int) []byte {
	rowBytes := w * 4
	out := make([]byte, rowBytes*h)
	for row := 0; row < h; row++ {
		srcOff := ((y+row)*fullW + x) * 4
		dstOff := row * rowBytes
		copy(out[dstOff:dstOff+rowBytes], buf[srcOff:srcOff+rowBytes])
	}
	return out
}

// downscaleBGRA resizes a top-down BGRA buffer to dstW x dstH using nearest-
// neighbor sampling — deliberately simple and fast rather than
// high-fidelity: this trades a softer image for materially less JPEG
// encode time and bytes-over-wire, worthwhile when the browser is
// displaying the stream smaller than native resolution anyway (its own
// drawImage() call scales the result back up to fill the canvas).
func downscaleBGRA(buf []byte, srcW, srcH, dstW, dstH int) []byte {
	if srcW == dstW && srcH == dstH {
		return buf
	}
	out := make([]byte, dstW*dstH*4)
	for dy := 0; dy < dstH; dy++ {
		sy := dy * srcH / dstH
		srcRow := sy * srcW * 4
		dstRow := dy * dstW * 4
		for dx := 0; dx < dstW; dx++ {
			sx := dx * srcW / dstW
			so := srcRow + sx*4
			do := dstRow + dx*4
			out[do], out[do+1], out[do+2], out[do+3] = buf[so], buf[so+1], buf[so+2], buf[so+3]
		}
	}
	return out
}

// newDXGICapturerRetrying retries newDXGICapturer a few times with a short
// delay between attempts. DuplicateOutput commonly fails with E_ACCESSDENIED
// (0x80070005) for a brief window after the previous holder of that output's
// duplication lock is gone but the OS hasn't released the lock yet — most
// reliably seen right after a sign-out/sign-in cycle, where the prior
// helper process was killed abruptly by Windows' own logoff teardown rather
// than getting a chance to call close() itself. Confirmed live: exactly this
// sequence left DXGI permanently unavailable for an entire session because
// the original one-shot attempt never got a second chance once the lock
// cleared a moment later — retrying transient DuplicateOutput failures is
// the standard, Microsoft-recommended handling for this API, not a one-shot
// attempt.
func newDXGICapturerRetrying(outputIndex, attempts int, delay time.Duration) (*dxgiCapturer, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		c, err := newDXGICapturer(outputIndex)
		if err == nil {
			return c, nil
		}
		lastErr = err
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	return nil, lastErr
}

func (c *dxgiCapturer) close() {
	comRelease(c.staging)
	comRelease(c.dupl)
	comRelease(c.context)
	comRelease(c.device)
}
