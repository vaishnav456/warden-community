package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"time"
)

const remotePerformanceInterval = 5 * time.Second
const remotePerformanceMaxMS = 60000.0
const remotePerformanceMaxCount uint64 = 1000000
const remotePerformanceMaxBytes uint64 = 1 << 30
const remoteHelperPerformanceMaxBytes = 4096

type remotePerformanceStage int

const (
	remoteDXGIWait remotePerformanceStage = iota
	remoteDXGIReadback
	remoteGDICapture
	remoteJPEGEncode
	remotePipeWrite
	remoteWSWriterWait
	remoteWSWrite
	remoteInputQueue
	remoteInputPipeWrite
	remoteInputPipeQueue
	remoteInputDispatch
	remotePerformanceStageCount
)

type remotePerformanceCounter int

const (
	remoteFullFrames remotePerformanceCounter = iota
	remotePartialFrames
	remoteDXGIFrames
	remoteGDIFrames
	remoteReplayFrames
	remoteDXGIIdle
	remoteDXGIAccumulated
	remoteEncodedBytes
	remotePerformanceCounterCount
)

type remoteTimingSummary struct {
	Samples uint64  `json:"samples"`
	MeanMS  float64 `json:"mean_ms"`
	MaxMS   float64 `json:"max_ms"`
}

type remotePerformanceTimings struct {
	DXGIWait       remoteTimingSummary `json:"dxgi_wait"`
	DXGIReadback   remoteTimingSummary `json:"dxgi_readback"`
	GDICapture     remoteTimingSummary `json:"gdi_capture"`
	JPEGEncode     remoteTimingSummary `json:"jpeg_encode"`
	PipeWrite      remoteTimingSummary `json:"pipe_write"`
	WSWriterWait   remoteTimingSummary `json:"ws_writer_wait"`
	WSWrite        remoteTimingSummary `json:"ws_write"`
	InputQueue     remoteTimingSummary `json:"input_queue"`
	InputPipeWrite remoteTimingSummary `json:"input_pipe_write"`
	InputPipeQueue remoteTimingSummary `json:"input_pipe_queue"`
	InputDispatch  remoteTimingSummary `json:"input_dispatch"`
}

type remotePerformanceWindow struct {
	WindowMS        float64                  `json:"window_ms"`
	NativeW         int                      `json:"native_w"`
	NativeH         int                      `json:"native_h"`
	EncodedW        int                      `json:"encoded_w"`
	EncodedH        int                      `json:"encoded_h"`
	InputQueueMax   int                      `json:"input_queue_max"`
	FullFrames      uint64                   `json:"full_frames"`
	PartialFrames   uint64                   `json:"partial_frames"`
	DXGIFrames      uint64                   `json:"dxgi_frames"`
	GDIFrames       uint64                   `json:"gdi_frames"`
	ReplayFrames    uint64                   `json:"replay_frames"`
	DXGIIdle        uint64                   `json:"dxgi_idle"`
	DXGIAccumulated uint64                   `json:"dxgi_accumulated"`
	EncodedBytes    uint64                   `json:"encoded_bytes"`
	Timings         remotePerformanceTimings `json:"timings"`
}

type remoteHelperPerformance struct {
	Version int                     `json:"version"`
	Window  remotePerformanceWindow `json:"window"`
}

type remotePerformanceReport struct {
	Type        string                   `json:"type"`
	Version     int                      `json:"version"`
	Service     remotePerformanceWindow  `json:"service"`
	Helper      *remotePerformanceWindow `json:"helper,omitempty"`
	HelperAgeMS *float64                 `json:"helper_age_ms,omitempty"`
}

type remoteTimingAccumulator struct {
	count uint64
	sumMS float64
	maxMS float64
}

// All storage is fixed-size and owned by one live session. No event, image,
// coordinate or input contents enter the accumulator or its JSON report.
type remotePerformance struct {
	mu                                   sync.Mutex
	started                              time.Time
	timings                              [remotePerformanceStageCount]remoteTimingAccumulator
	counters                             [remotePerformanceCounterCount]uint64
	nativeW, nativeH, encodedW, encodedH int
	inputQueueMax                        int
}

func newRemotePerformance(now time.Time) *remotePerformance {
	return &remotePerformance{started: now}
}

func remoteDurationMS(elapsed time.Duration) float64 {
	return math.Min(remotePerformanceMaxMS, math.Max(0, float64(elapsed)/float64(time.Millisecond)))
}

func (p *remotePerformance) observe(stage remotePerformanceStage, elapsed time.Duration) {
	if stage < 0 || stage >= remotePerformanceStageCount {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &p.timings[stage]
	if s.count >= remotePerformanceMaxCount {
		return
	}
	value := remoteDurationMS(elapsed)
	s.count++
	s.sumMS += value
	s.maxMS = math.Max(s.maxMS, value)
}

func (p *remotePerformance) add(counter remotePerformanceCounter, value uint64) {
	if counter < 0 || counter >= remotePerformanceCounterCount {
		return
	}
	limit := remotePerformanceMaxCount
	if counter == remoteEncodedBytes {
		limit = remotePerformanceMaxBytes
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if value > limit-p.counters[counter] {
		p.counters[counter] = limit
	} else {
		p.counters[counter] += value
	}
}

func (p *remotePerformance) dimensions(nativeW, nativeH, encodedW, encodedH int) {
	clamp := func(value int) int { return min(16384, max(0, value)) }
	p.mu.Lock()
	p.nativeW, p.nativeH, p.encodedW, p.encodedH = clamp(nativeW), clamp(nativeH), clamp(encodedW), clamp(encodedH)
	p.mu.Unlock()
}

func (p *remotePerformance) queueDepth(depth int) {
	p.mu.Lock()
	p.inputQueueMax = max(p.inputQueueMax, min(128, max(0, depth)))
	p.mu.Unlock()
}

func (p *remotePerformance) snapshot(now time.Time) remotePerformanceWindow {
	p.mu.Lock()
	defer p.mu.Unlock()
	var samples [remotePerformanceStageCount]remoteTimingSummary
	for index, timing := range p.timings {
		if timing.count > 0 {
			samples[index] = remoteTimingSummary{timing.count, math.Min(timing.maxMS, timing.sumMS/float64(timing.count)), timing.maxMS}
		}
	}
	c := p.counters
	window := remotePerformanceWindow{
		WindowMS: remoteDurationMS(now.Sub(p.started)),
		NativeW:  p.nativeW, NativeH: p.nativeH, EncodedW: p.encodedW, EncodedH: p.encodedH,
		InputQueueMax: p.inputQueueMax,
		FullFrames:    c[remoteFullFrames], PartialFrames: c[remotePartialFrames],
		DXGIFrames: c[remoteDXGIFrames], GDIFrames: c[remoteGDIFrames], ReplayFrames: c[remoteReplayFrames],
		DXGIIdle: c[remoteDXGIIdle], DXGIAccumulated: c[remoteDXGIAccumulated], EncodedBytes: c[remoteEncodedBytes],
		Timings: remotePerformanceTimings{samples[remoteDXGIWait], samples[remoteDXGIReadback], samples[remoteGDICapture],
			samples[remoteJPEGEncode], samples[remotePipeWrite], samples[remoteWSWriterWait], samples[remoteWSWrite],
			samples[remoteInputQueue], samples[remoteInputPipeWrite], samples[remoteInputPipeQueue], samples[remoteInputDispatch]},
	}
	p.started, p.inputQueueMax = now, 0
	p.timings = [remotePerformanceStageCount]remoteTimingAccumulator{}
	p.counters = [remotePerformanceCounterCount]uint64{}
	return window
}

func (w remotePerformanceWindow) valid() bool {
	finite := func(value float64) bool {
		return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= remotePerformanceMaxMS
	}
	if !finite(w.WindowMS) || w.InputQueueMax < 0 || w.InputQueueMax > 128 {
		return false
	}
	for _, dimension := range []int{w.NativeW, w.NativeH, w.EncodedW, w.EncodedH} {
		if dimension < 0 || dimension > 16384 {
			return false
		}
	}
	for _, count := range []uint64{w.FullFrames, w.PartialFrames, w.DXGIFrames, w.GDIFrames, w.ReplayFrames, w.DXGIIdle, w.DXGIAccumulated} {
		if count > remotePerformanceMaxCount {
			return false
		}
	}
	if w.EncodedBytes > remotePerformanceMaxBytes {
		return false
	}
	t := w.Timings
	for _, sample := range []remoteTimingSummary{t.DXGIWait, t.DXGIReadback, t.GDICapture, t.JPEGEncode, t.PipeWrite, t.WSWriterWait, t.WSWrite, t.InputQueue, t.InputPipeWrite, t.InputPipeQueue, t.InputDispatch} {
		if sample.Samples > remotePerformanceMaxCount || !finite(sample.MeanMS) || !finite(sample.MaxMS) || sample.MeanMS > sample.MaxMS ||
			(sample.Samples == 0 && (sample.MeanMS != 0 || sample.MaxMS != 0)) {
			return false
		}
	}
	return true
}

// Enforce exact case-sensitive keys and non-null values before struct decoding.
// The size cap makes this temporary JSON validation memory bounded too.
func remotePerformanceJSONFields(data []byte, fields []string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	values := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := values[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		values[key] = value
		if len(values) > len(fields) {
			return nil, false
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || decoder.Decode(new(any)) != io.EOF || len(values) != len(fields) {
		return nil, false
	}
	for _, field := range fields {
		value, exists := values[field]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
	}
	return values, true
}

func decodeRemoteHelperPerformance(data []byte) (remotePerformanceWindow, error) {
	var report remoteHelperPerformance
	invalid := func() (remotePerformanceWindow, error) {
		return remotePerformanceWindow{}, errors.New("invalid remote performance report")
	}
	if len(data) > remoteHelperPerformanceMaxBytes {
		return invalid()
	}
	envelope, ok := remotePerformanceJSONFields(data, []string{"version", "window"})
	if !ok {
		return invalid()
	}
	window, ok := remotePerformanceJSONFields(envelope["window"], []string{
		"window_ms", "native_w", "native_h", "encoded_w", "encoded_h", "input_queue_max",
		"full_frames", "partial_frames", "dxgi_frames", "gdi_frames", "replay_frames", "dxgi_idle", "dxgi_accumulated", "encoded_bytes", "timings",
	})
	if !ok {
		return invalid()
	}
	stages, ok := remotePerformanceJSONFields(window["timings"], []string{
		"dxgi_wait", "dxgi_readback", "gdi_capture", "jpeg_encode", "pipe_write", "ws_writer_wait", "ws_write", "input_queue", "input_pipe_write", "input_pipe_queue", "input_dispatch",
	})
	if !ok {
		return invalid()
	}
	for _, stage := range stages {
		if _, ok := remotePerformanceJSONFields(stage, []string{"samples", "mean_ms", "max_ms"}); !ok {
			return invalid()
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return invalid()
	}
	if decoder.Decode(new(any)) != io.EOF || report.Version != 1 || !report.Window.valid() {
		return invalid()
	}
	return report.Window, nil
}
