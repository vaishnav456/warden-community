package main

// Warden Home direct-only P2P acceptor. The control plane exchanges SDP; the
// data channel itself terminates here and forwards raw bytes only to this
// process's loopback TLS listener. Existing mTLS and signed grants therefore
// continue to authenticate and authorize every file operation.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

type p2pOffer struct {
	ID              string `json:"id"`
	EndpointID      string `json:"endpoint_id"`
	InitiatorNodeID string `json:"initiator_node_id"`
	OfferSDP        string `json:"offer_sdp"`
}
type p2pOfferResponse struct {
	Offers   []p2pOffer `json:"offers"`
	STUNURLs []string   `json:"stun_urls"`
}

var activeP2P sync.Map

const (
	homeP2PUDPMin uint16 = 55000
)

func newHomeP2PAPI() (*webrtc.API, error) {
	return sharedHomeP2PAPI()
}

type homeP2PConn struct {
	io.ReadWriteCloser
	pc      *webrtc.PeerConnection
	readMu  sync.Mutex
	readBuf bytes.Buffer
}

func (c *homeP2PConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readBuf.Len() == 0 {
		packet := make([]byte, 64*1024)
		n, err := c.ReadWriteCloser.Read(packet)
		if n > 0 {
			_, _ = c.readBuf.Write(packet[:n])
		}
		if err != nil && c.readBuf.Len() == 0 {
			return 0, err
		}
	}
	return c.readBuf.Read(p)
}

func (c *homeP2PConn) Close() error {
	err := c.ReadWriteCloser.Close()
	_ = c.pc.Close()
	return err
}
func (c *homeP2PConn) LocalAddr() net.Addr              { return homeP2PAddr("home-node") }
func (c *homeP2PConn) RemoteAddr() net.Addr             { return homeP2PAddr("peer-home-node") }
func (c *homeP2PConn) SetDeadline(time.Time) error      { return nil }
func (c *homeP2PConn) SetReadDeadline(time.Time) error  { return nil }
func (c *homeP2PConn) SetWriteDeadline(time.Time) error { return nil }

type homeP2PAddr string

func (a homeP2PAddr) Network() string { return "warden-home-p2p" }
func (a homeP2PAddr) String() string  { return string(a) }

func nodeControlPost(path string, body interface{}, result interface{}) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.WardenURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Warden-Home-Key", cfg.NodeKey)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Warden returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	if result == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(result)
}

func p2pLoopbackAddress() (string, error) {
	listen := cfg.Listen
	if !strings.Contains(listen, ":") {
		listen = ":" + listen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	if port == "" {
		return "", errors.New("P2P requires a TCP listen port")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func proxyDetachedChannel(rwc io.ReadWriteCloser) {
	target, err := p2pLoopbackAddress()
	if err != nil {
		_ = rwc.Close()
		return
	}
	local, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		_ = rwc.Close()
		return
	}
	closeBoth := sync.OnceFunc(func() { _ = rwc.Close(); _ = local.Close() })
	go func() { _, _ = io.Copy(local, rwc); closeBoth() }()
	go func() { _, _ = io.Copy(rwc, local); closeBoth() }()
}

func answerP2POffer(offer p2pOffer, stunURLs []string) {
	if _, loaded := activeP2P.LoadOrStore(offer.ID, true); loaded {
		return
	}
	reportFailure := func(err error) {
		_ = nodeControlPost("/api/home-node/p2p/answer", map[string]interface{}{
			"session_id": offer.ID, "error": err.Error(),
		}, nil)
		activeP2P.Delete(offer.ID)
	}
	api, err := newHomeP2PAPI()
	if err != nil {
		reportFailure(err)
		return
	}
	ice := []webrtc.ICEServer{}
	if len(stunURLs) > 0 {
		ice = append(ice, webrtc.ICEServer{URLs: stunURLs})
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: ice})
	if err != nil {
		reportFailure(err)
		return
	}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			_ = pc.Close()
			activeP2P.Delete(offer.ID)
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != "warden-home-tls" {
			_ = dc.Close()
			return
		}
		dc.OnOpen(func() {
			rwc, detachErr := dc.Detach()
			if detachErr != nil {
				_ = pc.Close()
				return
			}
			proxyDetachedChannel(rwc)
		})
	})
	if err = pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer.OfferSDP}); err != nil {
		_ = pc.Close()
		reportFailure(err)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		_ = pc.Close()
		reportFailure(err)
		return
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(answer); err != nil {
		_ = pc.Close()
		reportFailure(err)
		return
	}
	select {
	case <-gathered:
	case <-time.After(20 * time.Second):
		_ = pc.Close()
		reportFailure(errors.New("P2P candidate discovery timed out"))
		return
	}
	local := pc.LocalDescription()
	if local == nil {
		_ = pc.Close()
		reportFailure(errors.New("P2P answer was not created"))
		return
	}
	if err = nodeControlPost("/api/home-node/p2p/answer", map[string]interface{}{
		"session_id": offer.ID, "answer_sdp": local.SDP,
	}, nil); err != nil {
		_ = pc.Close()
		activeP2P.Delete(offer.ID)
		log.Printf("P2P answer failed: %v", err)
	}
}

func dialNodeP2P(peer peer) (net.Conn, error) {
	api, err := newHomeP2PAPI()
	if err != nil {
		return nil, err
	}
	ice := []webrtc.ICEServer{}
	if len(peer.STUNURLs) > 0 {
		ice = append(ice, webrtc.ICEServer{URLs: peer.STUNURLs})
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: ice})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { _ = pc.Close(); return nil, err }
	ready := make(chan io.ReadWriteCloser, 1)
	failed := make(chan error, 1)
	dc, err := pc.CreateDataChannel("warden-home-tls", nil)
	if err != nil {
		return fail(err)
	}
	dc.OnOpen(func() {
		rwc, detachErr := dc.Detach()
		if detachErr != nil {
			select {
			case failed <- detachErr:
			default:
			}
			return
		}
		select {
		case ready <- rwc:
		default:
			_ = rwc.Close()
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			select {
			case failed <- fmt.Errorf("P2P state %s", state.String()):
			default:
			}
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fail(err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(offer); err != nil {
		return fail(err)
	}
	select {
	case <-gathered:
	case <-time.After(20 * time.Second):
		return fail(errors.New("P2P candidate discovery timed out"))
	}
	local := pc.LocalDescription()
	if local == nil {
		return fail(errors.New("P2P offer was not created"))
	}
	var created struct {
		SessionID string `json:"session_id"`
	}
	if err = nodeControlPost("/api/home-node/p2p/offer", map[string]interface{}{
		"target_node_id": peer.TargetNodeID, "offer_sdp": local.SDP,
	}, &created); err != nil {
		return fail(fmt.Errorf("publish peer P2P offer: %w", err))
	}
	if created.SessionID == "" {
		return fail(errors.New("Warden returned no peer P2P session"))
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		var result struct {
			Status    string `json:"status"`
			AnswerSDP string `json:"answer_sdp"`
			Error     string `json:"error"`
		}
		if err = nodeControlPost("/api/home-node/p2p/result", map[string]interface{}{
			"session_id": created.SessionID,
		}, &result); err != nil {
			return fail(fmt.Errorf("poll peer P2P answer: %w", err))
		}
		if result.Status == "failed" {
			if result.Error == "" {
				result.Error = "peer Home Node rejected P2P negotiation"
			}
			return fail(errors.New(result.Error))
		}
		if result.Status == "answered" && result.AnswerSDP != "" {
			if err = pc.SetRemoteDescription(webrtc.SessionDescription{
				Type: webrtc.SDPTypeAnswer, SDP: result.AnswerSDP,
			}); err != nil {
				return fail(fmt.Errorf("apply peer P2P answer: %w", err))
			}
			select {
			case rwc := <-ready:
				return &homeP2PConn{ReadWriteCloser: rwc, pc: pc}, nil
			case err := <-failed:
				return fail(err)
			case <-time.After(25 * time.Second):
				return fail(errors.New("no direct peer P2P path; check UDP/STUN access"))
			}
		}
		time.Sleep(750 * time.Millisecond)
	}
	return fail(errors.New("peer Home Node did not answer the P2P offer"))
}

func homeP2PLoop(stop <-chan struct{}) {
	for {
		var response p2pOfferResponse
		if err := nodeControlPost("/api/home-node/p2p/offers", map[string]interface{}{}, &response); err != nil {
			log.Printf("P2P rendezvous poll deferred: %v", err)
		} else {
			for _, offer := range response.Offers {
				go answerP2POffer(offer, response.STUNURLs)
			}
		}
		select {
		case <-stop:
			return
		case <-time.After(2 * time.Second):
		}
	}
}
