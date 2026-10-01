package main

import (
	"io"
	"net/http"
	"sync"
	"time"
)

type homeConnectionQuality struct {
	Transport  string `json:"transport"`
	LatencyMS  int64  `json:"latency_ms"`
	DurationMS int64  `json:"duration_ms"`
	Bytes      int64  `json:"bytes"`
	Error      string `json:"error,omitempty"`
}
type homeMeasuredTransport struct {
	base http.RoundTripper
	sync.Mutex
	quality homeConnectionQuality
	start   time.Time
}

func (t *homeMeasuredTransport) setTransport(name string) {
	t.Lock()
	t.quality.Transport = name
	t.Unlock()
}

type homeMeasuredBody struct {
	io.ReadCloser
	t *homeMeasuredTransport
}

func (body homeMeasuredBody) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	body.t.Lock()
	body.t.quality.Bytes += int64(n)
	body.t.Unlock()
	return n, err
}
func (t *homeMeasuredTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	start := time.Now()
	clone := request.Clone(request.Context())
	if clone.Body != nil {
		clone.Body = homeMeasuredBody{clone.Body, t}
	}
	response, err := t.base.RoundTrip(clone)
	t.Lock()
	t.quality.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		t.quality.Error = "Transport request failed; inspect TLS, network and node availability"
	}
	t.Unlock()
	if err == nil && response.Body != nil {
		response.Body = homeMeasuredBody{response.Body, t}
	}
	return response, err
}
func (t *homeMeasuredTransport) snapshot() homeConnectionQuality {
	t.Lock()
	defer t.Unlock()
	q := t.quality
	q.DurationMS = time.Since(t.start).Milliseconds()
	return q
}
func (t *homeMeasuredTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
