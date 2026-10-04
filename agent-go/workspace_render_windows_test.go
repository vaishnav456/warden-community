package main

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"
)

func TestWorkspaceVectorSurfaceHasSmoothPremultipliedEdges(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	token, err := workspaceStartGraphics()
	if err != nil || token == 0 {
		t.Fatal("GDI+ startup failed", err)
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(token)
	font, _, _ := uiCreateFont.Call(^uintptr(14), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(font)
	small, _, _ := uiCreateFont.Call(^uintptr(10), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(small)
	p := &floatingWorkspace{size: 56, width: 340, height: 340, font: font, smallFont: small}
	// Verify real layered-window composition without showing any test UI.
	p.window, _, _ = uiCreateWindow.Call(0x00080088, uintptr(unsafe.Pointer(uiString("STATIC"))), 0, 0x80000000,
		0, 0, 320, 320, 0, 0, 0, 0)
	if p.window == 0 {
		t.Fatal("hidden composition test window failed")
	}
	defer uiDestroyWindow.Call(p.window)
	p.ready = true
	p.work = uiRect{0, 0, 1280, 720}
	p.anchorX, p.anchorY = 1244, 360
	for i := 0; i < 6; i++ {
		expanded := i%2 == 0
		p.layout(expanded)
		var actual uiRect
		ok, _, _ := user32DLL.NewProc("GetWindowRect").Call(p.window, uintptr(unsafe.Pointer(&actual)))
		wantSize := p.size
		if expanded {
			wantSize = p.width
		}
		if ok == 0 || actual.Left != p.position.X || actual.Top != p.position.Y || actual.Right-actual.Left != wantSize || actual.Bottom-actual.Top != wantSize {
			t.Fatalf("composition geometry mismatch: expanded=%v actual=%+v position=%+v size=%d", expanded, actual, p.position, wantSize)
		}
	}
	sheet := image.NewRGBA(image.Rect(0, 0, 480, 420))
	draw.Draw(sheet, sheet.Bounds(), image.NewUniform(color.RGBA{233, 238, 242, 255}), image.Point{}, draw.Src)
	for _, expanded := range []bool{false, true} {
		p.expanded = expanded
		if !p.render() {
			t.Fatal("per-pixel layered-window composition failed")
		}
		s := p.surface()
		if s == nil {
			t.Fatal("surface creation failed")
		}
		workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
		if !expanded {
			sample := int((s.width*28 + 12) * 4)
			if s.bits[sample+3] != 255 {
				s.close()
				t.Fatal("launcher interior is not opaque")
			}
			p.hoverID = 100
			hover := p.surface()
			p.hoverID = 0
			if hover == nil {
				s.close()
				t.Fatal("hover render failed")
			}
			workspaceGDIPlus.NewProc("GdipFlush").Call(hover.graphics, 1)
			if hover.bits[sample+3] != 255 {
				hover.close()
				s.close()
				t.Fatal("hover made launcher translucent")
			}
			if hover.bits[sample] == s.bits[sample] && hover.bits[sample+1] == s.bits[sample+1] && hover.bits[sample+2] == s.bits[sample+2] {
				hover.close()
				s.close()
				t.Fatal("hover does not change launcher color")
			}
			hover.close()
		}
		partial := 0
		bitmap := image.NewRGBA(image.Rect(0, 0, int(s.width), int(s.height)))
		for i := 0; i < len(s.bits); i += 4 {
			b, g, r, a := s.bits[i], s.bits[i+1], s.bits[i+2], s.bits[i+3]
			if r > a || g > a || b > a {
				s.close()
				t.Fatal("non-premultiplied alpha")
			}
			if a > 0 && a < 100 {
				partial++
			}
			copy(bitmap.Pix[i:i+4], []byte{r, g, b, a})
		}
		if partial == 0 {
			s.close()
			t.Fatal("no antialiased transparent edge")
		}
		if bitmap.RGBAAt(0, 0).A != 0 {
			s.close()
			t.Fatal("background is not transparent")
		}
		x, y := 26, 162
		if expanded {
			x, y = 105, 30
		}
		draw.Draw(sheet, image.Rect(x, y, x+int(s.width), y+int(s.height)), bitmap, image.Point{}, draw.Over)
		s.close()
	}
	if output := os.Getenv("WARDEN_WORKSPACE_RENDER_TEST_OUT"); output != "" {
		if !filepath.IsAbs(output) {
			t.Fatal("render output must be absolute")
		}
		f, err := os.Create(output)
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(f, sheet)
		closeErr := f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}
