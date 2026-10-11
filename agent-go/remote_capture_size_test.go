package main

import "testing"

func TestRemoteCaptureSizeFitsEachViewportAxisWithoutUpscaling(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		nativeW, nativeH, viewW, viewH int
		wantW, wantH                   int
	}{
		{"wide-short", 1920, 1080, 4000, 540, 960, 540},
		{"tall-narrow", 1920, 1080, 960, 4000, 960, 540},
		{"square", 1920, 1080, 1000, 1000, 1000, 562},
		{"native", 1920, 1080, 1920, 1080, 1920, 1080},
		{"oversized", 1920, 1080, 4000, 4000, 1920, 1080},
		{"near-native", 1920, 1080, 1919, 1080, 1919, 1079},
		{"near-native-height", 20, 10, 20, 9, 18, 9},
		{"no-preference", 1920, 1080, 0, 0, 1920, 1080},
		{"missing-axis", 1920, 1080, 0, 540, 1920, 1080},
		{"negative-axis", 1920, 1080, 960, -1, 1920, 1080},
		{"one-pixel", 3, 2, 1, 1, 1, 1},
		{"invalid-native", 0, 1080, 960, 540, 0, 1080},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, h := remoteCaptureSize(tc.nativeW, tc.nativeH, tc.viewW, tc.viewH)
			if w != tc.wantW || h != tc.wantH {
				t.Fatalf("got %dx%d, want %dx%d", w, h, tc.wantW, tc.wantH)
			}
		})
	}
}
