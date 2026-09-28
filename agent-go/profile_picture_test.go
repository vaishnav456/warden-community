package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func testProfilePhotoDataURL(t *testing.T, width, height int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return profilePhotoPrefix + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestDecodeProfilePhotoAcceptsBoundedPNG(t *testing.T) {
	img, err := decodeProfilePhoto(testProfilePhotoDataURL(t, 256, 128))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 256 || img.Bounds().Dy() != 128 {
		t.Fatalf("unexpected dimensions: %v", img.Bounds())
	}
}

func TestDecodeProfilePhotoRejectsUnexpectedFormatsAndDimensions(t *testing.T) {
	if _, err := decodeProfilePhoto("data:image/jpeg;base64,AAAA"); err == nil {
		t.Fatal("expected JPEG data URL to be rejected")
	}
	if _, err := decodeProfilePhoto(testProfilePhotoDataURL(t, 513, 1)); err == nil {
		t.Fatal("expected oversized dimensions to be rejected")
	}
}

func TestSquareProfilePhotoCropsAndResizes(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 200, 100))
	got := squareProfilePhoto(src, 48)
	if got.Bounds().Dx() != 48 || got.Bounds().Dy() != 48 {
		t.Fatalf("unexpected output dimensions: %v", got.Bounds())
	}
}

func TestRemoveUserProfilePictureRejectsUnsafeSID(t *testing.T) {
	for _, sid := range []string{"", `..\\..\\Windows`, `S-1-5-21\\..\\other`} {
		if err := removeUserProfilePicture(sid); err == nil {
			t.Fatalf("expected unsafe SID %q to be rejected", sid)
		}
	}
}
