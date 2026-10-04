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

func TestWardenUIOnlyAcceptsItsOwnActionButtons(t *testing.T) {
	u := &wardenUI{approval: true, allow: 101, deny: 202}
	for _, c := range []struct {
		id, source uintptr
		want       bool
	}{
		{6, 0, false}, {6, 202, false}, {6, 303, false}, {6, 101, true}, {7, 202, true}, {7, 101, false}, {20, 101, false},
	} {
		if got := u.validAction(c.id, c.source); got != c.want {
			t.Fatalf("action %d from %d: %v", c.id, c.source, got)
		}
	}
	u.approval = false
	if u.validAction(6, 101) {
		t.Fatal("notification allowed approval")
	}
}
func TestModernWindowsPromptDesignFitsSmallWindows(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	token, err := workspaceStartGraphics()
	if err != nil || token == 0 {
		t.Fatal("GDI+ unavailable", err)
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(token)
	newFont := func(size int32, weight uintptr) uintptr {
		font, _, _ := uiCreateFont.Call(uintptr(-int64(size)), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
		if font == 0 {
			t.Fatal("font creation failed")
		}
		t.Cleanup(func() { procDeleteObject.Call(font) })
		return font
	}
	font, heading, small := newFont(16, 400), newFont(20, 600), newFont(13, 400)
	sheet := image.NewRGBA(image.Rect(0, 0, 980, 630))
	draw.Draw(sheet, sheet.Bounds(), image.NewUniform(color.RGBA{233, 238, 242, 255}), image.Point{}, draw.Src)
	for index, width := range []int32{600, 320} {
		height := int32(550)
		if width == 320 {
			height = 420
		}
		u := &wardenUI{width: width, height: height, scale: 1, font: font, headingFont: heading, smallFont: small,
			instruction: "Your IT team requests remote access", footer: "Allow only if you recognize this request. Closing this window denies access.",
			severity: "info", approval: true, allowLabel: "Allow this session", denyLabel: "Deny access"}
		s := u.surface()
		if s == nil {
			t.Fatal("prompt render failed")
		}
		s.textLeft("PREVIEW ONLY\n\nRequested by: Your IT team\nDevice: Development laptop\n\nYou stay in control. This sample does not grant access.", 36, 152, width-66, height-280, font, 0xffdeeff2)
		workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
		buttonWidth := (width - 72) / 2
		u.paintButton(&workspaceDrawItem{ControlID: 6, DC: s.dc, Rect: uiRect{24, height - 57, 24 + buttonWidth, height - 19}})
		u.paintButton(&workspaceDrawItem{ControlID: 7, State: 0x10, DC: s.dc, Rect: uiRect{width - 24 - buttonWidth, height - 57, width - 24, height - 19}})
		gdi32DLL.NewProc("GdiFlush").Call()
		bitmap := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
		for i := 0; i < len(s.bits); i += 4 {
			b, g, r, a := s.bits[i], s.bits[i+1], s.bits[i+2], s.bits[i+3]
			if a != 255 {
				s.close()
				t.Fatal("opaque dialog has transparent pixels")
			}
			copy(bitmap.Pix[i:i+4], []byte{r, g, b, a})
		}
		x := 30
		if index == 1 {
			x = 660
		}
		draw.Draw(sheet, image.Rect(x, 30, x+int(width), 30+int(height)), bitmap, image.Point{}, draw.Src)
		s.close()
	}
	if output := os.Getenv("WARDEN_PROMPT_RENDER_TEST_OUT"); output != "" {
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
