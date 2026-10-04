//go:build !warden_core

package main

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"
)

func TestTicketFormStyleSurfaces(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	token, err := workspaceStartGraphics()
	if err != nil || token == 0 {
		t.Fatal(err)
	}
	defer workspaceGDIPlus.NewProc("GdiplusShutdown").Call(token)
	font, _, _ := uiCreateFont.Call(^uintptr(15), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	defer procDeleteObject.Call(font)
	u := &wardenUI{scale: 1, font: font}
	f := &ticketFormUI{u: u}
	sheet := workspaceNewSurface(480, 230)
	if sheet == nil {
		t.Fatal("sheet failed")
	}
	defer sheet.close()
	workspaceGDIPlus.NewProc("GdipGraphicsClear").Call(sheet.graphics, 0xff1e3542)
	for i, focused := range []bool{false, true} {
		s := ticketFieldSurface(u, 432, 42, focused)
		if s == nil {
			t.Fatal("field failed")
		}
		s.textLeft("A short summary of the issue", 12, 0, 400, 42, font, 0xffedf7f9)
		workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
		at := (int(s.width)*30 + 420) * 4
		if s.bits[at] != 0x36 || s.bits[at+1] != 0x2b || s.bits[at+2] != 0x17 {
			s.close()
			t.Fatal("field does not use Warden dark surface")
		}
		gdi32DLL.NewProc("BitBlt").Call(sheet.dc, 24, uintptr(24+i*66), 432, 42, s.dc, 0, 0, 0x00cc0020)
		s.close()
	}
	choice := f.choiceSurface(ticketControl{options: []string{"General support"}}, 432, 42, false)
	if choice == nil {
		t.Fatal("dropdown render failed")
	}
	defer choice.close()
	workspaceGDIPlus.NewProc("GdipFlush").Call(choice.graphics, 1)
	gdi32DLL.NewProc("BitBlt").Call(sheet.dc, 24, 156, 432, 42, choice.dc, 0, 0, 0x00cc0020)
	if _, plain := ticketFieldColors(false); plain == 0 {
		t.Fatal("missing border")
	}
	_, plain := ticketFieldColors(false)
	_, focused := ticketFieldColors(true)
	if plain == focused {
		t.Fatal("focus border unchanged")
	}
	if output := os.Getenv("WARDEN_TICKET_STYLE_TEST_OUT"); output != "" {
		if !filepath.IsAbs(output) {
			t.Fatal("absolute output required")
		}
		bitmap := image.NewRGBA(image.Rect(0, 0, 480, 230))
		for i := 0; i < len(sheet.bits); i += 4 {
			copy(bitmap.Pix[i:i+4], []byte{sheet.bits[i+2], sheet.bits[i+1], sheet.bits[i], sheet.bits[i+3]})
		}
		file, err := os.Create(output)
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(file, bitmap)
		closeErr := file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}
