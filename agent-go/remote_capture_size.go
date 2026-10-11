package main

// remoteCaptureSize fits the encoded image inside the requested viewport
// without upscaling. The desktop and input coordinates stay at native size.
func remoteCaptureSize(nativeW, nativeH, requestedW, requestedH int) (int, int) {
	if nativeW <= 0 || nativeH <= 0 || requestedW <= 0 || requestedH <= 0 {
		return nativeW, nativeH
	}
	scale := 1.0
	if s := float64(requestedW) / float64(nativeW); s < scale {
		scale = s
	}
	if s := float64(requestedH) / float64(nativeH); s < scale {
		scale = s
	}
	w, h := int(float64(nativeW)*scale), int(float64(nativeH)*scale)
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	return w, h
}
