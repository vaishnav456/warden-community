package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	profilePhotoPrefix   = "data:image/png;base64,"
	maxProfilePhotoBytes = 512 * 1024
	maxProfilePhotoSide  = 512
)

var windowsAccountPictureSizes = []int{32, 40, 48, 96, 192, 240, 448}

func decodeProfilePhoto(dataURL string) (image.Image, error) {
	if dataURL == "" {
		return nil, nil
	}
	if !strings.HasPrefix(dataURL, profilePhotoPrefix) {
		return nil, fmt.Errorf("profile photo must be a PNG data URL")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(dataURL, profilePhotoPrefix))
	if err != nil {
		return nil, fmt.Errorf("decode profile photo: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxProfilePhotoBytes {
		return nil, fmt.Errorf("profile photo must be between 1 and %d bytes", maxProfilePhotoBytes)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode profile photo PNG: %w", err)
	}
	bounds := img.Bounds()
	if bounds.Dx() < 1 || bounds.Dy() < 1 || bounds.Dx() > maxProfilePhotoSide || bounds.Dy() > maxProfilePhotoSide {
		return nil, fmt.Errorf("profile photo dimensions must be between 1 and %d pixels", maxProfilePhotoSide)
	}
	return img, nil
}

func squareProfilePhoto(src image.Image, size int) image.Image {
	b := src.Bounds()
	side := b.Dx()
	if b.Dy() < side {
		side = b.Dy()
	}
	x0 := b.Min.X + (b.Dx()-side)/2
	y0 := b.Min.Y + (b.Dy()-side)/2
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		sy := y0 + y*side/size
		for x := 0; x < size; x++ {
			sx := x0 + x*side/size
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

func writePNGAtomic(path string, img image.Image) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".warden-profile-*.png")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := png.Encode(tmp, img); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Remove(path)
	return os.Rename(tmpName, path)
}

// applyUserProfilePicture installs the same tenant-supplied portrait into the
// Windows account-picture registry contract used by the lock/sign-in screen.
// It never reads or uploads pictures belonging to unmanaged local accounts.
func applyUserProfilePicture(username, dataURL string) error {
	img, err := decodeProfilePhoto(dataURL)
	if err != nil || img == nil {
		return err
	}
	sid, _, err := lookupWindowsAccountIdentity(username)
	if err != nil {
		return fmt.Errorf("resolve profile-photo account SID: %w", err)
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	dir := filepath.Join(programData, "Microsoft", "User Account Pictures", sid)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create account-picture directory: %w", err)
	}

	paths := make(map[int]string, len(windowsAccountPictureSizes))
	for _, size := range windowsAccountPictureSizes {
		path := filepath.Join(dir, fmt.Sprintf("Image%d.png", size))
		if err := writePNGAtomic(path, squareProfilePhoto(img, size)); err != nil {
			return fmt.Errorf("write %dpx account picture: %w", size, err)
		}
		paths[size] = path
	}

	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\` + sid
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open account-picture registry key: %w", err)
	}
	defer key.Close()
	for _, size := range windowsAccountPictureSizes {
		if err := key.SetStringValue(fmt.Sprintf("Image%d", size), paths[size]); err != nil {
			return fmt.Errorf("register %dpx account picture: %w", size, err)
		}
	}
	return nil
}

// removeUserProfilePicture removes only Warden's per-SID account-picture
// artifacts. Windows does not remove these files or the AccountPicture key
// when a local account is deleted, which otherwise leaves tenant-supplied
// profile data behind and may show the old portrait if the SID is restored.
func removeUserProfilePicture(sid string) error {
	if !strings.HasPrefix(sid, "S-1-") || strings.ContainsAny(sid, `\\/:*?"<>|`) {
		return fmt.Errorf("invalid account SID")
	}
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\` + sid
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, keyPath); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("delete account-picture registry key: %w", err)
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	if err := os.RemoveAll(filepath.Join(programData, "Microsoft", "User Account Pictures", sid)); err != nil {
		return fmt.Errorf("delete account-picture directory: %w", err)
	}
	return nil
}
