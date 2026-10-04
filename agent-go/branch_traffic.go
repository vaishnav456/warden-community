package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type branchTraffic struct {
	BusinessStart int `json:"business_start"`
	BusinessEnd   int `json:"business_end"`
	BusinessKBPS  int `json:"business_kbps"`
	OffhoursKBPS  int `json:"offhours_kbps"`
}

var trafficState = struct {
	sync.Mutex
	policy  *branchTraffic
	fetched time.Time
	limiter *rate.Limiter
}{}

func inTrafficWindow(start, end, hour int) bool {
	if start == end {
		return true
	}
	if start < end {
		return hour >= start && hour < end
	}
	return hour >= start || hour < end
}
func (p branchTraffic) valid() bool {
	return p.BusinessStart >= 0 && p.BusinessStart <= 23 && p.BusinessEnd >= 0 && p.BusinessEnd <= 23 && p.BusinessKBPS >= 16 && p.BusinessKBPS <= 1048576 && p.OffhoursKBPS >= 16 && p.OffhoursKBPS <= 1048576
}
func (p branchTraffic) bytesPerSecond(now time.Time) int {
	value := p.OffhoursKBPS
	if inTrafficWindow(p.BusinessStart, p.BusinessEnd, now.UTC().Hour()) {
		value = p.BusinessKBPS
	}
	return value * 1024
}
func agentConfigGET(path string, target interface{}) error {
	clientMu.Lock()
	client := httpClient
	clientMu.Unlock()
	if client == nil {
		return errors.New("secure communications unavailable")
	}
	rawURL, err := validatePinnedDownloadURL(strings.TrimRight(serverURL(), "/") + path)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-Agent-Key", apiKey)
	if err := addDeviceRequestProof(request, nil); err != nil {
		return err
	}
	copyClient := *client
	copyClient.Timeout = 10 * time.Second
	copyClient.CheckRedirect = rejectRedirect
	response, err := copyClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("configuration HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(target)
}
func refreshBranchTraffic() error {
	trafficState.Lock()
	defer trafficState.Unlock()
	if time.Since(trafficState.fetched) < 5*time.Minute {
		return nil
	}
	var result struct {
		Traffic *branchTraffic `json:"traffic"`
	}
	if err := agentConfigGET("/api/agent/traffic-config", &result); err != nil {
		// Old servers do not expose this opt-in capability. Other failures never
		// silently discard a policy and make a constrained download unlimited.
		if strings.Contains(err.Error(), "HTTP 404") {
			trafficState.fetched = time.Now()
			return nil
		}
		if !trafficState.fetched.IsZero() && time.Since(trafficState.fetched) < 15*time.Minute {
			return nil
		}
		return err
	}
	if result.Traffic != nil && !result.Traffic.valid() {
		return errors.New("invalid branch traffic policy")
	}
	trafficState.policy = result.Traffic
	trafficState.fetched = time.Now()
	if result.Traffic == nil {
		trafficState.limiter = nil
	} else if trafficState.limiter == nil {
		trafficState.limiter = rate.NewLimiter(rate.Limit(result.Traffic.bytesPerSecond(time.Now())), 16*1024)
	}
	return nil
}

type trafficReadCloser struct {
	io.ReadCloser
	ctx context.Context
}

func (body trafficReadCloser) Read(p []byte) (int, error) {
	if len(p) > 16*1024 {
		p = p[:16*1024]
	}
	trafficState.Lock()
	limiter := trafficState.limiter
	policy := trafficState.policy
	if limiter != nil && policy != nil {
		limiter.SetLimit(rate.Limit(policy.bytesPerSecond(time.Now())))
	}
	trafficState.Unlock()
	if limiter != nil {
		if err := limiter.WaitN(body.ctx, len(p)); err != nil {
			return 0, err
		}
	}
	return body.ReadCloser.Read(p)
}

type branchTrafficTransport struct{ base http.RoundTripper }

func (transport branchTrafficTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	if clone.Body != nil {
		clone.Body = trafficReadCloser{clone.Body, clone.Context()}
	}
	response, err := transport.base.RoundTrip(clone)
	if err == nil && response.Body != nil {
		response.Body = trafficReadCloser{response.Body, request.Context()}
	}
	return response, err
}
func (transport branchTrafficTransport) CloseIdleConnections() {
	if closer, ok := transport.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func packageCacheResponse(rawURL, sha string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 5 || strings.Join(parts[:3], "/") != "api/agent/apps" || parts[4] != "download" {
		return nil, nil
	}
	appID := parts[3]
	var result struct {
		Cache *homeNode `json:"cache"`
	}
	if err = agentConfigGET("/api/agent/package-cache?app_id="+url.QueryEscape(appID)+"&sha256="+url.QueryEscape(sha), &result); err != nil {
		return nil, err
	}
	if result.Cache == nil {
		return nil, nil
	}
	client, err := homeHTTPClient(*result.Cache, "")
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodGet, homeNodeURL(*result.Cache)+"/v1/package?sha256="+url.QueryEscape(sha), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+result.Cache.Grant)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 || response.Header.Get("X-Warden-SHA256") != sha {
		response.Body.Close()
		return nil, errors.New("cache did not supply a verified package")
	}
	return response, nil
}
