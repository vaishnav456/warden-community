package main

import "time"

// remoteCaptureState keeps deltas tied to the capture source that produced
// their baseline. Each DXGI snapshot is the complete current desktop image,
// including changes already sent as partial updates.
type remoteCaptureState struct {
	pixels                      []byte
	width, height               int
	baseline                    bool
	bootstrapSent               bool
	encodedWidth, encodedHeight int
	lastSent, lastFull          time.Time
}

func (s *remoteCaptureState) reset() { *s = remoteCaptureState{} }

func (s *remoteCaptureState) remember(pixels []byte, width, height int) {
	// grabBGRA allocates a new owned buffer on each acquisition.
	s.pixels, s.width, s.height = pixels, width, height
	s.bootstrapSent = true
}

func (s *remoteCaptureState) shouldReplay(now time.Time, encodedWidth, encodedHeight int) bool {
	return len(s.pixels) > 0 && (!s.baseline ||
		encodedWidth != s.encodedWidth || encodedHeight != s.encodedHeight ||
		now.Sub(s.lastSent) >= 2*time.Second)
}

func (s *remoteCaptureState) needsBootstrap() bool {
	return len(s.pixels) == 0 && !s.bootstrapSent
}

func (s *remoteCaptureState) needsFull(now time.Time, haveDirty bool, dirtyArea, totalArea, encodedWidth, encodedHeight int) bool {
	return !s.baseline || !haveDirty || dirtyArea >= totalArea*6/10 ||
		encodedWidth != s.encodedWidth || encodedHeight != s.encodedHeight ||
		now.Sub(s.lastFull) >= 2*time.Second
}

func (s *remoteCaptureState) sentFull(now time.Time, encodedWidth, encodedHeight int) {
	s.baseline = true
	s.encodedWidth, s.encodedHeight = encodedWidth, encodedHeight
	s.lastSent, s.lastFull = now, now
}

func (s *remoteCaptureState) sentPartial(now time.Time) { s.lastSent = now }

func (s *remoteCaptureState) invalidateBaseline() {
	s.pixels = nil
	s.baseline = false
}

func (s *remoteCaptureState) sentGDI(now time.Time) {
	// A GDI image is not a valid base for a subsequent DXGI delta.
	s.invalidateBaseline()
	s.bootstrapSent = true
	s.lastSent = now
}

func captureUpdateRects(dirty []dxgiRect, moves []dxgiMoveRect) []dxgiRect {
	// The copied DXGI surface already contains moved pixels at their new
	// positions. Include those destinations in the region we transmit.
	for _, move := range moves {
		dirty = append(dirty, move.DestinationRect)
	}
	return dirty
}
