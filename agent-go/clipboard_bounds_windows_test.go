package main

import "testing"

func TestClipboardReadsNeverScanPastAllocation(t *testing.T) {
	if boundedClipboardText([]uint16{'h', 'i', 0, 'x'}) != "hi" {
		t.Fatal("valid clipboard rejected")
	}
	for _, buffer := range [][]uint16{nil, {'x'}, {'x', 'y'}} {
		if boundedClipboardText(buffer) != "" {
			t.Fatal("unterminated clipboard accepted")
		}
	}
}
