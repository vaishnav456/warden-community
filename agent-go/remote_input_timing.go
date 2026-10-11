package main

import (
	"encoding/binary"
	"errors"
	"time"
)

const remoteTimedInputTag byte = 'Q'
const remoteTimedInputHeaderSize = 8
const remoteInputMaxBytes = 1 << 20 // Same limit as the remote WebSocket input.

// Only the service supplies the host-uptime timestamp. Input JSON is retained
// byte-for-byte, including button/key releases; it never enters telemetry.
func buildRemoteTimedInput(payload []byte, tickMS uint64) ([]byte, error) {
	if len(payload) == 0 || len(payload) > remoteInputMaxBytes {
		return nil, errors.New("invalid timed remote input size")
	}
	framed := make([]byte, remoteTimedInputHeaderSize+len(payload))
	binary.LittleEndian.PutUint64(framed, tickMS)
	copy(framed[remoteTimedInputHeaderSize:], payload)
	return framed, nil
}

// Invalid clocks suppress a measurement, never a structurally valid input.
// Very old input still dispatches (especially releases), with its wait clamped
// to the fixed diagnostic bound. The shared Windows clock has coarse ms ticks.
func decodeRemoteTimedInput(payload []byte, nowMS uint64) ([]byte, time.Duration, bool, error) {
	if len(payload) <= remoteTimedInputHeaderSize || len(payload) > remoteTimedInputHeaderSize+remoteInputMaxBytes {
		return nil, 0, false, errors.New("invalid timed remote input size")
	}
	tickMS := binary.LittleEndian.Uint64(payload[:remoteTimedInputHeaderSize])
	raw := payload[remoteTimedInputHeaderSize:]
	if tickMS == 0 || tickMS > nowMS {
		return raw, 0, false, nil
	}
	elapsedMS := nowMS - tickMS
	if elapsedMS > uint64(remotePerformanceMaxMS) {
		elapsedMS = uint64(remotePerformanceMaxMS)
	}
	return raw, time.Duration(elapsedMS) * time.Millisecond, true, nil
}
