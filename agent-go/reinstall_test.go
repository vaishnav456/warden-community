package main

import (
	"bytes"
	"testing"
)

func TestEncodeUTF16LEForTaskScheduler(t *testing.T) {
	encoded := encodeUTF16LE(`<?xml version="1.0" encoding="UTF-16"?><Task>Warden ✓</Task>`)
	if len(encoded) < 4 || encoded[0] != 0xff || encoded[1] != 0xfe {
		t.Fatalf("missing UTF-16LE byte-order mark: %x", encoded[:min(len(encoded), 4)])
	}
	if !bytes.Contains(encoded, []byte{'<', 0, '?', 0, 'x', 0, 'm', 0, 'l', 0}) {
		t.Fatal("XML body was not encoded as UTF-16LE")
	}
}
