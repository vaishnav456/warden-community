package main

// Per-pixel-alpha vector rendering. No downloaded assets, webview, scripts or
// external processes are involved in drawing the user-session launcher.
import (
	"golang.org/x/sys/windows"
	"math"
	"unsafe"
)

var workspaceGDIPlus = windows.NewLazySystemDLL("gdiplus.dll")

type workspaceGDIStartup struct {
	Version                        uint32
	Debug                          uintptr
	SuppressThread, SuppressCodecs int32
}
type workspaceBitmapInfo struct {
	Size                   uint32
	Width, Height          int32
	Planes, BitCount       uint16
	Compression, ImageSize uint32
	XPels, YPels           int32
	Used, Important        uint32
}
type workspaceSurface struct {
	dc, bitmap, previous, image, graphics uintptr
	bits                                  []byte
	width, height                         int32
}
type workspaceRectF struct{ X, Y, Width, Height float32 }

func workspaceStartGraphics() (uintptr, error) {
	var token uintptr
	input := workspaceGDIStartup{Version: 1}
	status, _, err := workspaceGDIPlus.NewProc("GdiplusStartup").Call(uintptr(unsafe.Pointer(&token)), uintptr(unsafe.Pointer(&input)), 0)
	if status != 0 {
		return 0, err
	}
	return token, nil
}
func workspaceNewSurface(width, height int32) *workspaceSurface {
	if width < 1 || height < 1 || width > 2048 || height > 2048 {
		return nil
	}
	s := &workspaceSurface{width: width, height: height}
	s.dc, _, _ = gdi32DLL.NewProc("CreateCompatibleDC").Call(0)
	if s.dc == 0 {
		return nil
	}
	info := workspaceBitmapInfo{Size: 40, Width: width, Height: -height, Planes: 1, BitCount: 32}
	var pixels uintptr
	s.bitmap, _, _ = gdi32DLL.NewProc("CreateDIBSection").Call(s.dc, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if s.bitmap == 0 || pixels == 0 {
		s.close()
		return nil
	}
	s.previous, _, _ = procSelectObject.Call(s.dc, s.bitmap)
	s.bits = unsafe.Slice((*byte)(unsafe.Pointer(pixels)), int(width*height*4))
	// PixelFormat32bppPARGB is premultiplied BGRA, as required by ULW_ALPHA.
	status, _, _ := workspaceGDIPlus.NewProc("GdipCreateBitmapFromScan0").Call(uintptr(width), uintptr(height), uintptr(width*4), 0x000e200b, pixels, uintptr(unsafe.Pointer(&s.image)))
	if status != 0 {
		s.close()
		return nil
	}
	status, _, _ = workspaceGDIPlus.NewProc("GdipGetImageGraphicsContext").Call(s.image, uintptr(unsafe.Pointer(&s.graphics)))
	if status != 0 {
		s.close()
		return nil
	}
	workspaceGDIPlus.NewProc("GdipSetSmoothingMode").Call(s.graphics, 4)
	workspaceGDIPlus.NewProc("GdipSetPixelOffsetMode").Call(s.graphics, 4)
	workspaceGDIPlus.NewProc("GdipSetTextRenderingHint").Call(s.graphics, 4)
	workspaceGDIPlus.NewProc("GdipGraphicsClear").Call(s.graphics, 0)
	return s
}
func (s *workspaceSurface) close() {
	if s.graphics != 0 {
		workspaceGDIPlus.NewProc("GdipDeleteGraphics").Call(s.graphics)
	}
	if s.image != 0 {
		workspaceGDIPlus.NewProc("GdipDisposeImage").Call(s.image)
	}
	if s.previous != 0 {
		procSelectObject.Call(s.dc, s.previous)
	}
	if s.bitmap != 0 {
		procDeleteObject.Call(s.bitmap)
	}
	if s.dc != 0 {
		gdi32DLL.NewProc("DeleteDC").Call(s.dc)
	}
}
func (s *workspaceSurface) circle(x, y, d int32, color uint32) {
	var brush uintptr
	workspaceGDIPlus.NewProc("GdipCreateSolidFill").Call(uintptr(color), uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		return
	}
	workspaceGDIPlus.NewProc("GdipFillEllipseI").Call(s.graphics, brush, uintptr(x), uintptr(y), uintptr(d), uintptr(d))
	workspaceGDIPlus.NewProc("GdipDeleteBrush").Call(brush)
}

func (s *workspaceSurface) roundedRect(x, y, w, h, r int32, color uint32) {
	if w <= 0 || h <= 0 {
		return
	}
	if r > w/2 {
		r = w / 2
	}
	if r > h/2 {
		r = h / 2
	}
	var brush uintptr
	workspaceGDIPlus.NewProc("GdipCreateSolidFill").Call(uintptr(color), uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		return
	}
	defer workspaceGDIPlus.NewProc("GdipDeleteBrush").Call(brush)
	workspaceGDIPlus.NewProc("GdipFillRectangleI").Call(s.graphics, brush, uintptr(x+r), uintptr(y), uintptr(w-2*r), uintptr(h))
	workspaceGDIPlus.NewProc("GdipFillRectangleI").Call(s.graphics, brush, uintptr(x), uintptr(y+r), uintptr(w), uintptr(h-2*r))
	for _, corner := range []workspacePoint{{x, y}, {x + w - 2*r, y}, {x, y + h - 2*r}, {x + w - 2*r, y + h - 2*r}} {
		workspaceGDIPlus.NewProc("GdipFillEllipseI").Call(s.graphics, brush, uintptr(corner.X), uintptr(corner.Y), uintptr(2*r), uintptr(2*r))
	}
}

func (s *workspaceSurface) gradientCircle(x, y, d int32, top, bottom uint32) {
	rect := struct{ X, Y, Width, Height int32 }{x, y, d, d}
	var brush uintptr
	status, _, _ := workspaceGDIPlus.NewProc("GdipCreateLineBrushFromRectI").Call(uintptr(unsafe.Pointer(&rect)), uintptr(top), uintptr(bottom), 1, 4, uintptr(unsafe.Pointer(&brush)))
	if status != 0 || brush == 0 {
		s.circle(x, y, d, bottom)
		return
	}
	workspaceGDIPlus.NewProc("GdipFillEllipseI").Call(s.graphics, brush, uintptr(x), uintptr(y), uintptr(d), uintptr(d))
	workspaceGDIPlus.NewProc("GdipDeleteBrush").Call(brush)
}
func (s *workspaceSurface) shadow(x, y, d int32) {
	for spread := int32(8); spread >= 1; spread-- {
		s.circle(x-spread, y-spread+3, d+spread*2, 0x04071118)
	}
}
func (s *workspaceSurface) arc(cx, cy, r int32, start, end float64, color uint32) {
	for i := 0; i < 24; i++ {
		a, b := start+(end-start)*float64(i)/24, start+(end-start)*float64(i+1)/24
		x1, y1 := cx+int32(math.Round(math.Cos(a)*float64(r))), cy+int32(math.Round(math.Sin(a)*float64(r)))
		x2, y2 := cx+int32(math.Round(math.Cos(b)*float64(r))), cy+int32(math.Round(math.Sin(b)*float64(r)))
		s.line(x1, y1, x2, y2, color)
	}
}

func (s *workspaceSurface) line(x1, y1, x2, y2 int32, color uint32) {
	// GdipCreatePen1 takes a floating-point width; CreatePen2 also does.
	// A brush-filled polygon avoids float ABI calls and keeps smooth 2px strokes.
	dx, dy := float64(x2-x1), float64(y2-y1)
	length := math.Hypot(dx, dy)
	if length == 0 {
		s.circle(x1-1, y1-1, 2, color)
		return
	}
	nx, ny := -dy/length, dx/length
	points := []workspaceRectF{
		{X: float32(float64(x1) + nx), Y: float32(float64(y1) + ny)},
		{X: float32(float64(x2) + nx), Y: float32(float64(y2) + ny)},
		{X: float32(float64(x2) - nx), Y: float32(float64(y2) - ny)},
		{X: float32(float64(x1) - nx), Y: float32(float64(y1) - ny)},
	}
	// GpPointF has two floats, not a rectangle.
	pairs := make([]float32, 0, 8)
	for _, p := range points {
		pairs = append(pairs, p.X, p.Y)
	}
	var brush uintptr
	workspaceGDIPlus.NewProc("GdipCreateSolidFill").Call(uintptr(color), uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		return
	}
	workspaceGDIPlus.NewProc("GdipFillPolygon").Call(s.graphics, brush, uintptr(unsafe.Pointer(&pairs[0])), 4, 0)
	workspaceGDIPlus.NewProc("GdipDeleteBrush").Call(brush)
	s.circle(x1-1, y1-1, 2, color)
	s.circle(x2-1, y2-1, 2, color)
}
func (s *workspaceSurface) text(label string, x, y, w, h int32, font uintptr, color uint32) {
	s.textAligned(label, x, y, w, h, font, color, 1)
}
func (s *workspaceSurface) textLeft(label string, x, y, w, h int32, font uintptr, color uint32) {
	s.textAligned(label, x, y, w, h, font, color, 0)
}
func (s *workspaceSurface) textAligned(label string, x, y, w, h int32, font uintptr, color uint32, align uintptr) {
	old, _, _ := procSelectObject.Call(s.dc, font)
	var gpfont, format, brush uintptr
	workspaceGDIPlus.NewProc("GdipCreateFontFromDC").Call(s.dc, uintptr(unsafe.Pointer(&gpfont)))
	procSelectObject.Call(s.dc, old)
	if gpfont == 0 {
		return
	}
	defer workspaceGDIPlus.NewProc("GdipDeleteFont").Call(gpfont)
	workspaceGDIPlus.NewProc("GdipCreateStringFormat").Call(0, 0, uintptr(unsafe.Pointer(&format)))
	if format == 0 {
		return
	}
	defer workspaceGDIPlus.NewProc("GdipDeleteStringFormat").Call(format)
	workspaceGDIPlus.NewProc("GdipSetStringFormatAlign").Call(format, align)
	workspaceGDIPlus.NewProc("GdipSetStringFormatLineAlign").Call(format, align)
	workspaceGDIPlus.NewProc("GdipCreateSolidFill").Call(uintptr(color), uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		return
	}
	defer workspaceGDIPlus.NewProc("GdipDeleteBrush").Call(brush)
	rect := workspaceRectF{float32(x), float32(y), float32(w), float32(h)}
	workspaceGDIPlus.NewProc("GdipDrawString").Call(s.graphics, uintptr(unsafe.Pointer(uiString(label))), ^uintptr(0), gpfont, uintptr(unsafe.Pointer(&rect)), format, brush)
}

// Filled cubic paths give consistent curved glyphs and clean transparent holes.
type workspaceIconPath struct {
	handle uintptr
	x, y   int32
}

func (p workspaceIconPath) line(x1, y1, x2, y2 int32) {
	workspaceGDIPlus.NewProc("GdipAddPathLineI").Call(p.handle, uintptr(p.x+x1), uintptr(p.y+y1), uintptr(p.x+x2), uintptr(p.y+y2))
}
func (p workspaceIconPath) curve(x1, y1, x2, y2, x3, y3, x4, y4 int32) {
	workspaceGDIPlus.NewProc("GdipAddPathBezierI").Call(p.handle, uintptr(p.x+x1), uintptr(p.y+y1), uintptr(p.x+x2), uintptr(p.y+y2), uintptr(p.x+x3), uintptr(p.y+y3), uintptr(p.x+x4), uintptr(p.y+y4))
}
func (p workspaceIconPath) close() { workspaceGDIPlus.NewProc("GdipClosePathFigure").Call(p.handle) }
func (p workspaceIconPath) box(x, y, w, h, r int32) {
	workspaceGDIPlus.NewProc("GdipStartPathFigure").Call(p.handle)
	p.line(x+r, y, x+w-r, y)
	p.curve(x+w-r, y, x+w, y, x+w, y, x+w, y+r)
	p.line(x+w, y+r, x+w, y+h-r)
	p.curve(x+w, y+h-r, x+w, y+h, x+w, y+h, x+w-r, y+h)
	p.line(x+w-r, y+h, x+r, y+h)
	p.curve(x+r, y+h, x, y+h, x, y+h, x, y+h-r)
	p.line(x, y+h-r, x, y+r)
	p.curve(x, y+r, x, y, x, y, x+r, y)
	p.close()
}
func (s *workspaceSurface) icon(id uintptr, cx, cy int32, color uint32) {
	if id == 103 {
		s.line(cx-5, cy-5, cx+5, cy+5, color)
		s.line(cx+5, cy-5, cx-5, cy+5, color)
		return
	}
	var path, brush uintptr
	workspaceGDIPlus.NewProc("GdipCreatePath").Call(0, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer workspaceGDIPlus.NewProc("GdipDeletePath").Call(path)
	p := workspaceIconPath{path, cx - 12, cy - 12}
	switch id {
	case 102:
		p.curve(0, 11, 0, 4, 4, 0, 12, 0)
		p.curve(12, 0, 20, 0, 24, 4, 24, 11)
		p.line(24, 11, 22, 11)
		p.curve(22, 11, 22, 5, 18, 2, 12, 2)
		p.curve(12, 2, 6, 2, 2, 5, 2, 11)
		p.line(2, 11, 0, 11)
		p.close()
		p.box(0, 12, 5, 8, 2)
		p.box(19, 12, 5, 8, 2)
	case 101:
		p.line(4, 2, 20, 2)
		p.curve(20, 2, 24, 2, 24, 4, 24, 6)
		p.line(24, 6, 24, 16)
		p.curve(24, 16, 24, 19, 22, 20, 20, 20)
		p.line(20, 20, 10, 20)
		p.line(10, 20, 3, 24)
		p.line(3, 24, 4, 20)
		p.curve(4, 20, 1, 20, 0, 18, 0, 16)
		p.line(0, 16, 0, 6)
		p.curve(0, 6, 0, 3, 1, 2, 4, 2)
		p.close()
		p.box(2, 4, 20, 14, 2)
	case 105:
		p.line(12, 0, 22, 4)
		p.line(22, 4, 22, 11)
		p.curve(22, 11, 22, 17, 17, 22, 12, 24)
		p.curve(12, 24, 7, 22, 2, 17, 2, 11)
		p.line(2, 11, 2, 4)
		p.line(2, 4, 12, 0)
		p.close()
		p.line(12, 2, 20, 5)
		p.line(20, 5, 20, 11)
		p.curve(20, 11, 20, 16, 16, 20, 12, 22)
		p.curve(12, 22, 8, 20, 4, 16, 4, 11)
		p.line(4, 11, 4, 5)
		p.line(4, 5, 12, 2)
		p.close()
	case 106:
		workspaceGDIPlus.NewProc("GdipAddPathEllipseI").Call(path, uintptr(cx-12), uintptr(cy-11), 14, 14)
		workspaceGDIPlus.NewProc("GdipAddPathEllipseI").Call(path, uintptr(cx-10), uintptr(cy-9), 10, 10)
	default:
		return
	}
	workspaceGDIPlus.NewProc("GdipCreateSolidFill").Call(uintptr(color), uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		return
	}
	workspaceGDIPlus.NewProc("GdipFillPath").Call(s.graphics, brush, path)
	workspaceGDIPlus.NewProc("GdipDeleteBrush").Call(brush)
	if id == 102 {
		s.line(cx+10, cy+8, cx+6, cy+11, color)
		s.line(cx+6, cy+11, cx+2, cy+11, color)
	}
	if id == 106 {
		s.line(cx, cy+1, cx+10, cy+11, color)
		s.line(cx+5, cy+6, cx+9, cy+2, color)
	}
}
