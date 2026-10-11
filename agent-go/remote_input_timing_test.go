package main

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func TestRemoteTimedInputRetainsReleaseBytesAndCopiesSource(t *testing.T) {
	for _, event := range []string{
		`{ "type": "mouseup", "button":"right", "x":11, "y":22 }`,
		`{"type":"keyup","key":"\u00e9","ctrlKey":false}`,
		`{"type":"scroll","delta":-2}`,
	} {
		raw := []byte(event)
		framed, err := buildRemoteTimedInput(raw, 1234)
		if err != nil || len(framed) != len(raw)+remoteTimedInputHeaderSize || binary.LittleEndian.Uint64(framed[:remoteTimedInputHeaderSize]) != 1234 {
			t.Fatalf("wrong internal timing envelope: size=%d error=%v", len(framed), err)
		}
		raw[0] = '!'
		decoded, elapsed, measured, err := decodeRemoteTimedInput(framed, 1500)
		if err != nil || !bytes.Equal(decoded, []byte(event)) || !measured || elapsed != 266*time.Millisecond {
			t.Fatalf("release/input content changed or timing lost: raw=%q elapsed=%v measured=%v error=%v", decoded, elapsed, measured, err)
		}
	}
}

func TestRemoteTimedInputInvalidClocksPreserveReleases(t *testing.T) {
	raw := []byte(`{"type":"mouseup","button":"left"}`)
	for _, clocks := range [][2]uint64{{0, 500}, {501, 500}, {0, 0}, {math.MaxUint64, 500}} {
		framed, err := buildRemoteTimedInput(raw, clocks[0])
		if err != nil {
			t.Fatal(err)
		}
		decoded, elapsed, measured, err := decodeRemoteTimedInput(framed, clocks[1])
		if err != nil || measured || elapsed != 0 || !bytes.Equal(decoded, raw) {
			t.Fatalf("invalid timing discarded or changed a release: ticks=%v elapsed=%v measured=%v error=%v", clocks, elapsed, measured, err)
		}
	}
}

func TestRemoteTimedInputLargeWaitsClampBeforeDurationConversion(t *testing.T) {
	for _, test := range []struct {
		tick, now uint64
		want      time.Duration
	}{
		{100, 100, 0}, {100, 60100, time.Minute}, {100, 60101, time.Minute},
		{1, math.MaxUint64, time.Minute}, {math.MaxUint64 - 123, math.MaxUint64, 123 * time.Millisecond},
	} {
		raw := []byte(`{"type":"keyup","key":"Alt"}`)
		framed, err := buildRemoteTimedInput(raw, test.tick)
		if err != nil {
			t.Fatal(err)
		}
		decoded, elapsed, measured, err := decodeRemoteTimedInput(framed, test.now)
		if err != nil || !measured || elapsed != test.want || !bytes.Equal(decoded, raw) {
			t.Fatalf("old queued release overflowed or disappeared: tick=%d now=%d elapsed=%v measured=%v error=%v", test.tick, test.now, elapsed, measured, err)
		}
	}
}

func TestRemoteTimedInputBoundsAndTruncatedFrames(t *testing.T) {
	for _, size := range []int{0, remoteInputMaxBytes + 1} {
		if framed, err := buildRemoteTimedInput(make([]byte, size), 1); err == nil || framed != nil {
			t.Fatalf("invalid raw size accepted: %d", size)
		}
	}
	for _, size := range []int{0, 1, remoteTimedInputHeaderSize - 1, remoteTimedInputHeaderSize, remoteTimedInputHeaderSize + remoteInputMaxBytes + 1} {
		if raw, elapsed, measured, err := decodeRemoteTimedInput(make([]byte, size), 2); err == nil || raw != nil || elapsed != 0 || measured {
			t.Fatalf("malformed timing envelope accepted: %d", size)
		}
	}
	raw := bytes.Repeat([]byte{' '}, remoteInputMaxBytes)
	framed, err := buildRemoteTimedInput(raw, 100)
	if err != nil {
		t.Fatal(err)
	}
	decoded, elapsed, measured, err := decodeRemoteTimedInput(framed, 101)
	if err != nil || !measured || elapsed != time.Millisecond || !bytes.Equal(decoded, raw) {
		t.Fatal("maximum bounded frame did not retain the existing input-size limit")
	}
}
