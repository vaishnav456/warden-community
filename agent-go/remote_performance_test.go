package main

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func remoteTestSummaries(t remotePerformanceTimings) []remoteTimingSummary {
	return []remoteTimingSummary{t.DXGIWait, t.DXGIReadback, t.GDICapture, t.JPEGEncode,
		t.PipeWrite, t.WSWriterWait, t.WSWrite, t.InputQueue, t.InputPipeWrite, t.InputPipeQueue, t.InputDispatch}
}

func remoteTestHelperJSON(t *testing.T, w remotePerformanceWindow) []byte {
	t.Helper()
	data, err := json.Marshal(remoteHelperPerformance{Version: 1, Window: w})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRemotePerformanceSeparatesClickBacklogAndResetsWindow(t *testing.T) {
	start := time.Unix(100, 0)
	p := newRemotePerformance(start)
	p.dimensions(2560, 1440, 1280, 720)
	for _, delay := range []time.Duration{200 * time.Millisecond, time.Second, 3 * time.Second} {
		p.observe(remoteInputQueue, delay)
		p.observe(remoteInputPipeWrite, 2*time.Millisecond)
		p.observe(remoteInputPipeQueue, 600*time.Millisecond)
		p.observe(remoteInputDispatch, time.Millisecond)
	}
	p.observe(remoteJPEGEncode, 5*time.Millisecond)
	p.add(remoteFullFrames, 1)
	p.add(remotePartialFrames, 14)
	p.add(remoteEncodedBytes, 9000)
	p.queueDepth(64)
	p.queueDepth(2)
	first := p.snapshot(start.Add(remotePerformanceInterval))
	if first.WindowMS != 5000 || first.InputQueueMax != 64 {
		t.Fatalf("wrong reporting window or queue peak: %+v", first)
	}
	if got := first.Timings.InputQueue; got != (remoteTimingSummary{Samples: 3, MeanMS: 1400, MaxMS: 3000}) {
		t.Fatalf("click queue delay not retained separately: %+v", got)
	}
	if first.Timings.InputPipeWrite.MeanMS != 2 || first.Timings.InputPipeQueue.MeanMS != 600 || first.Timings.InputDispatch.MeanMS != 1 || first.Timings.JPEGEncode.MeanMS != 5 {
		t.Fatalf("click queue delay contaminated other stages: %+v", first.Timings)
	}
	if first.FullFrames != 1 || first.PartialFrames != 14 || first.EncodedBytes != 9000 || !first.valid() {
		t.Fatalf("wrong counters or invalid first report: %+v", first)
	}
	second := p.snapshot(start.Add(2 * remotePerformanceInterval))
	want := remotePerformanceWindow{WindowMS: 5000, NativeW: 2560, NativeH: 1440, EncodedW: 1280, EncodedH: 720}
	if second != want {
		t.Fatalf("five-second report retained old delay, count or queue peak: %+v", second)
	}
	p.dimensions(1920, 1080, 960, 540)
	p.observe(remoteInputQueue, 10*time.Millisecond)
	third := p.snapshot(start.Add(3 * remotePerformanceInterval))
	if third.Timings.InputQueue != (remoteTimingSummary{Samples: 1, MeanMS: 10, MaxMS: 10}) || third.NativeW != 1920 {
		t.Fatalf("new window is cumulative or lost current dimensions: %+v", third)
	}
	if first.NativeW != 2560 || first.Timings.InputQueue.MeanMS != 1400 {
		t.Fatal("a later observation mutated an earlier report")
	}
}

func TestRemotePerformanceEveryStageHasIndependentTiming(t *testing.T) {
	start := time.Unix(100, 0)
	p := newRemotePerformance(start)
	for stage := remotePerformanceStage(0); stage < remotePerformanceStageCount; stage++ {
		p.observe(stage, time.Duration(stage+1)*time.Millisecond)
		p.observe(stage, time.Duration(stage+2)*time.Millisecond)
	}
	p.observe(-1, time.Hour)
	p.observe(remotePerformanceStageCount, time.Hour)
	w := p.snapshot(start.Add(time.Second))
	for index, got := range remoteTestSummaries(w.Timings) {
		want := remoteTimingSummary{Samples: 2, MeanMS: float64(index) + 1.5, MaxMS: float64(index + 2)}
		if got != want {
			t.Fatalf("stage %d was lost or mixed with another stage: got %+v want %+v", index, got, want)
		}
	}
}

func TestRemotePerformanceBoundsWithoutWrapping(t *testing.T) {
	start := time.Unix(100, 0)
	p := newRemotePerformance(start)
	p.observe(remoteInputQueue, -time.Second)
	p.observe(remoteInputQueue, time.Duration(math.MaxInt64))
	for counter := remotePerformanceCounter(0); counter < remotePerformanceCounterCount; counter++ {
		p.add(counter, 1)
		p.add(counter, math.MaxUint64)
		p.add(counter, 1)
	}
	p.add(-1, math.MaxUint64)
	p.add(remotePerformanceCounterCount, math.MaxUint64)
	p.dimensions(-1, math.MaxInt, 16384, 16385)
	p.queueDepth(-1)
	p.queueDepth(math.MaxInt)
	w := p.snapshot(start.Add(time.Hour))
	if w.Timings.InputQueue != (remoteTimingSummary{Samples: 2, MeanMS: 30000, MaxMS: 60000}) {
		t.Fatalf("duration bounds failed: %+v", w.Timings.InputQueue)
	}
	if w.WindowMS != 60000 || w.NativeW != 0 || w.NativeH != 16384 || w.EncodedW != 16384 || w.EncodedH != 16384 || w.InputQueueMax != 128 {
		t.Fatalf("report bounds failed: %+v", w)
	}
	for _, got := range []uint64{w.FullFrames, w.PartialFrames, w.DXGIFrames, w.GDIFrames, w.ReplayFrames, w.DXGIIdle, w.DXGIAccumulated} {
		if got != remotePerformanceMaxCount {
			t.Fatalf("counter wrapped or exceeded cap: %d", got)
		}
	}
	if w.EncodedBytes != remotePerformanceMaxBytes || !w.valid() {
		t.Fatalf("bounded report is invalid: %+v", w)
	}
	if back := p.snapshot(start); back.WindowMS != 0 {
		t.Fatalf("backward clock produced negative window: %v", back.WindowMS)
	}
	if next := p.snapshot(start.Add(time.Second)); next.WindowMS != 1000 {
		t.Fatalf("report clock did not reset after backward clock: %v", next.WindowMS)
	}
}

func TestRemotePerformanceSampleCapAndFixedStorage(t *testing.T) {
	start := time.Unix(100, 0)
	p := newRemotePerformance(start)
	for index := uint64(0); index < remotePerformanceMaxCount+10; index++ {
		p.observe(remoteInputQueue, time.Millisecond)
	}
	p.observe(remoteInputQueue, time.Hour)
	w := p.snapshot(start.Add(remotePerformanceInterval))
	if w.Timings.InputQueue != (remoteTimingSummary{Samples: remotePerformanceMaxCount, MeanMS: 1, MaxMS: 1}) {
		t.Fatalf("samples or total grew beyond cap: %+v", w.Timings.InputQueue)
	}
	if data := remoteTestHelperJSON(t, w); len(data) >= remoteHelperPerformanceMaxBytes {
		t.Fatalf("a million measurements exceeded bounded report size: %d", len(data))
	}
	allocations := testing.AllocsPerRun(100, func() {
		for index := 0; index < 1000; index++ {
			p.observe(remoteInputQueue, time.Millisecond)
			p.add(remoteEncodedBytes, 1024)
			p.queueDepth(32)
		}
		_ = p.snapshot(start.Add(remotePerformanceInterval))
	})
	if allocations != 0 {
		t.Fatalf("hot-path measurements retained per-event storage: %v allocations", allocations)
	}
}

func TestRemotePerformanceConcurrentReportsConserveMeasurements(t *testing.T) {
	start := time.Unix(100, 0)
	p := newRemotePerformance(start)
	const workers, observations = 8, 2000
	var group sync.WaitGroup
	begin := make(chan struct{})
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-begin
			for index := 0; index < observations; index++ {
				p.observe(remoteInputQueue, time.Millisecond)
				p.add(remoteFullFrames, 1)
			}
		}()
	}
	close(begin)
	var samples, frames uint64
	for index := 1; index <= 100; index++ {
		w := p.snapshot(start.Add(time.Duration(index) * time.Millisecond))
		if !w.valid() || (w.Timings.InputQueue.Samples > 0 && w.Timings.InputQueue.MeanMS != 1) {
			t.Fatalf("concurrent snapshot contained inconsistent timing: %+v", w)
		}
		samples += w.Timings.InputQueue.Samples
		frames += w.FullFrames
	}
	group.Wait()
	w := p.snapshot(start.Add(time.Second))
	samples += w.Timings.InputQueue.Samples
	frames += w.FullFrames
	if samples != workers*observations || frames != workers*observations {
		t.Fatalf("observations lost across concurrent resets: samples=%d frames=%d", samples, frames)
	}
}

func TestRemoteHelperPerformanceRoundTripAtBounds(t *testing.T) {
	w := remotePerformanceWindow{
		WindowMS: 60000, NativeW: 16384, NativeH: 16384, EncodedW: 16384, EncodedH: 16384,
		InputQueueMax: 128, FullFrames: remotePerformanceMaxCount, PartialFrames: remotePerformanceMaxCount,
		DXGIFrames: remotePerformanceMaxCount, GDIFrames: remotePerformanceMaxCount, ReplayFrames: remotePerformanceMaxCount,
		DXGIIdle: remotePerformanceMaxCount, DXGIAccumulated: remotePerformanceMaxCount, EncodedBytes: remotePerformanceMaxBytes,
	}
	sample := remoteTimingSummary{Samples: remotePerformanceMaxCount, MeanMS: 60000, MaxMS: 60000}
	w.Timings = remotePerformanceTimings{sample, sample, sample, sample, sample, sample, sample, sample, sample, sample, sample}
	data := remoteTestHelperJSON(t, w)
	if len(data) > remoteHelperPerformanceMaxBytes {
		t.Fatalf("valid bounded report cannot fit internal pipe envelope: %d", len(data))
	}
	decoded, err := decodeRemoteHelperPerformance(append(data, '\n', ' ', '\t'))
	if err != nil || decoded != w {
		t.Fatalf("valid maximum report rejected or changed: %+v %v", decoded, err)
	}
	var object any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	var checkNumeric func(any)
	checkNumeric = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for _, item := range value {
				checkNumeric(item)
			}
		case float64:
		default:
			t.Fatalf("helper report unexpectedly includes nonnumeric event content: %T", value)
		}
	}
	checkNumeric(object)
}

func TestRemoteHelperPerformanceRejectsMalformedOrUnboundedReports(t *testing.T) {
	valid := string(remoteTestHelperJSON(t, remotePerformanceWindow{}))
	cases := map[string]string{
		"duplicate version":       strings.Replace(valid, `"version":1`, `"version":2,"version":1`, 1),
		"duplicate window field":  strings.Replace(valid, `"window_ms":0`, `"window_ms":-1,"window_ms":0`, 1),
		"duplicate stage":         strings.Replace(valid, `"input_queue":{"samples":0,"mean_ms":0,"max_ms":0}`, `"input_queue":null,"input_queue":{"samples":0,"mean_ms":0,"max_ms":0}`, 1),
		"duplicate summary field": strings.Replace(valid, `"mean_ms":0`, `"mean_ms":-1,"mean_ms":0`, 1),
		"missing window":          `{"version":1}`, "null window": `{"version":1,"window":null}`,
		"missing envelope version":     strings.Replace(valid, `"version":1,`, "", 1),
		"missing window clock":         strings.Replace(valid, `"window_ms":0,`, "", 1),
		"case changed window key":      strings.Replace(valid, `"window_ms":0`, `"Window_MS":0`, 1),
		"null window count":            strings.Replace(valid, `"full_frames":0`, `"full_frames":null`, 1),
		"missing timing summary field": strings.Replace(valid, `"samples":0,`, "", 1),
		"null timing summary field":    strings.Replace(valid, `"samples":0`, `"samples":null`, 1),
		"null stage":                   strings.Replace(valid, `"input_dispatch":{"samples":0,"mean_ms":0,"max_ms":0}`, `"input_dispatch":null`, 1),
		"case changed stage":           strings.Replace(valid, `"input_queue":`, `"Input_Queue":`, 1),
		"case changed summary key":     strings.Replace(valid, `"mean_ms":0`, `"Mean_MS":0`, 1),
		"null timings":                 strings.Replace(valid, `"timings":{`, `"timings":null,"ignored_timings":{`, 1),
		"empty":                        "", "malformed": "{", "wrong version": strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"unknown envelope": strings.TrimSuffix(valid, "}") + `,"input":"private"}`,
		"unknown window":   strings.Replace(valid, `"window":{`, `"window":{"mouse_x":5,`, 1),
		"unknown stage":    strings.Replace(valid, `"timings":{`, `"timings":{"input_contents":{},`, 1),
		"second document":  valid + `{}`, "trailing garbage": valid + `private`,
		"too large":                 valid + strings.Repeat(" ", remoteHelperPerformanceMaxBytes),
		"negative duration":         strings.Replace(valid, `"window_ms":0`, `"window_ms":-1`, 1),
		"duration above cap":        strings.Replace(valid, `"window_ms":0`, `"window_ms":60001`, 1),
		"negative dimensions":       strings.Replace(valid, `"native_w":0`, `"native_w":-1`, 1),
		"dimension above cap":       strings.Replace(valid, `"encoded_h":0`, `"encoded_h":16385`, 1),
		"queue above cap":           strings.Replace(valid, `"input_queue_max":0`, `"input_queue_max":129`, 1),
		"negative count":            strings.Replace(valid, `"full_frames":0`, `"full_frames":-1`, 1),
		"count above cap":           strings.Replace(valid, `"partial_frames":0`, `"partial_frames":1000001`, 1),
		"integer overflow":          strings.Replace(valid, `"full_frames":0`, `"full_frames":18446744073709551616`, 1),
		"bytes above cap":           strings.Replace(valid, `"encoded_bytes":0`, `"encoded_bytes":1073741825`, 1),
		"empty sample nonzero mean": strings.Replace(valid, `"mean_ms":0`, `"mean_ms":1`, 1),
		"sample above cap":          strings.Replace(valid, `"samples":0`, `"samples":1000001`, 1),
		"mean greater than max":     strings.Replace(valid, `"samples":0,"mean_ms":0,"max_ms":0`, `"samples":1,"mean_ms":2,"max_ms":1`, 1),
		"max above cap":             strings.Replace(valid, `"samples":0,"mean_ms":0,"max_ms":0`, `"samples":1,"mean_ms":1,"max_ms":60001`, 1),
		"nonfinite JSON":            strings.Replace(valid, `"window_ms":0`, `"window_ms":1e999`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRemoteHelperPerformance([]byte(data)); err == nil {
				t.Fatal("malformed or out-of-bounds helper report accepted")
			}
		})
	}
}

func TestRemotePerformanceWindowRejectsNonfiniteNumbers(t *testing.T) {
	for _, number := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if (remotePerformanceWindow{WindowMS: number}).valid() {
			t.Fatal("nonfinite clock accepted")
		}
		for _, field := range []string{"MeanMS", "MaxMS"} {
			w := remotePerformanceWindow{}
			sample := remoteTimingSummary{Samples: 1, MeanMS: 1, MaxMS: 1}
			reflect.ValueOf(&sample).Elem().FieldByName(field).SetFloat(number)
			w.Timings.InputQueue = sample
			if w.valid() {
				t.Fatalf("nonfinite %s accepted", field)
			}
		}
	}
	if _, err := decodeRemoteHelperPerformance(bytes.Repeat([]byte{' '}, remoteHelperPerformanceMaxBytes+1)); err == nil {
		t.Fatal("oversize report accepted before decoding")
	}
}
