package main

// Warden Home P2P acceptor. Direct channels and encrypted relay streams
// terminate here and forward bytes only to this process's loopback TLS
// listener. Existing mTLS and signed grants authenticate every file operation.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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
	homeP2PUDPMax uint16 = 55099
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
func (c *homeP2PConn) LocalAddr() net.Addr  { return homeP2PAddr("home-node") }
func (c *homeP2PConn) RemoteAddr() net.Addr { return homeP2PAddr("peer-home-node") }
func (c *homeP2PConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *homeP2PConn) SetReadDeadline(t time.Time) error {
	if conn, ok := c.ReadWriteCloser.(interface{ SetReadDeadline(time.Time) error }); ok {
		return conn.SetReadDeadline(t)
	}
	return nil
}
func (c *homeP2PConn) SetWriteDeadline(t time.Time) error {
	if conn, ok := c.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return conn.SetWriteDeadline(t)
	}
	return nil
}

// Each HTTP connection gets a fresh tunnel, including retries after an idle
// close. TLS still validates the requested node hostname and its certificate.
func newHomeP2PTLSTransport(config *tls.Config, dial func() (net.Conn, error)) *http.Transport {
	transport := &http.Transport{TLSClientConfig: config}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tunnel, err := dial()
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		candidate := config.Clone()
		candidate.ServerName = host
		conn := tls.Client(tunnel, candidate)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = tunnel.Close()
			return nil, err
		}
		return conn, nil
	}
	return transport
}

type homeP2PAddr string

func (a homeP2PAddr) Network() string { return "warden-home-p2p" }
func (a homeP2PAddr) String() string  { return string(a) }

type homeRelayConn struct {
	ws      *websocket.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	reader  io.Reader
}

func (c *homeRelayConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		for c.reader == nil {
			messageType, reader, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if messageType == websocket.BinaryMessage {
				c.reader = reader
			}
		}
		n, err := c.reader.Read(p)
		if n > 0 {
			if errors.Is(err, io.EOF) {
				c.reader = nil
			}
			return n, nil
		}
		if errors.Is(err, io.EOF) {
			c.reader = nil
			continue
		}
		return 0, err
	}
}

func (c *homeRelayConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	writer, err := c.ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, writeErr := writer.Write(p)
	closeErr := writer.Close()
	if writeErr != nil {
		return n, writeErr
	}
	return n, closeErr
}

func (c *homeRelayConn) Close() error         { return c.ws.Close() }
func (c *homeRelayConn) LocalAddr() net.Addr  { return homeP2PAddr("home-node-relay") }
func (c *homeRelayConn) RemoteAddr() net.Addr { return homeP2PAddr("warden-relay") }
func (c *homeRelayConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *homeRelayConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *homeRelayConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

func dialHomeRelay(sessionID, side string) (net.Conn, error) {
	base, err := url.Parse(strings.TrimRight(cfg.WardenURL, "/"))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, errors.New("invalid Warden relay URL")
	}
	if base.Scheme == "https" {
		base.Scheme = "wss"
	} else {
		base.Scheme = "ws"
	}
	base.Path = "/home-relay/" + side + "/" + url.PathEscape(sessionID)
	base.RawQuery = ""
	headers := http.Header{}
	headers.Set("X-Warden-Home-Key", cfg.NodeKey)
	dialer := websocket.Dialer{HandshakeTimeout: 30 * time.Second, Proxy: http.ProxyFromEnvironment}
	ws, response, err := dialer.Dial(base.String(), headers)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("encrypted relay connection failed: %w", err)
	}
	ws.SetReadLimit(128 * 1024)
	return &homeRelayConn{ws: ws}, nil
}

func acceptHomeRelay(sessionID string) {
	conn, err := dialHomeRelay(sessionID, "node")
	if err != nil {
		log.Printf("Home relay standby failed for session %s: %v", sessionID, err)
		return
	}
	proxyDetachedChannel(conn)
}

func fallbackNodeRelay(sessionID string, directErr error) (net.Conn, error) {
	conn, relayErr := dialHomeRelay(sessionID, "source")
	if relayErr == nil {
		log.Printf("Direct peer P2P unavailable; using end-to-end encrypted HTTPS relay")
		return conn, nil
	}
	return nil, fmt.Errorf("direct peer P2P failed (%v); HTTPS relay failed (%v)", directErr, relayErr)
}

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
	resp, err := homeControlClient().Do(req)
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
	proxyHomeStream(rwc, func() (net.Conn, error) {
		return net.DialTimeout("tcp", target, 10*time.Second)
	})
}

func proxyHomeStream(rwc io.ReadWriteCloser, dial func() (net.Conn, error)) {
	go func() {
		// A relay target waits on standby while ICE tries the direct path.
		// Opening TLS now would start the server's handshake timeout before
		// the initiator joins. Wait for its encrypted ClientHello first.
		first := make([]byte, 64*1024)
		n, err := rwc.Read(first)
		if err != nil || n == 0 {
			_ = rwc.Close()
			return
		}
		local, err := dial()
		if err != nil {
			_ = rwc.Close()
			return
		}
		closeBoth := sync.OnceFunc(func() { _ = rwc.Close(); _ = local.Close() })
		defer closeBoth()
		if _, err := io.Copy(local, bytes.NewReader(first[:n])); err != nil {
			return
		}
		go func() { _, _ = io.Copy(rwc, local); closeBoth() }()
		_, _ = io.Copy(local, rwc)
	}()
}

func answerP2POffer(offer p2pOffer, stunURLs []string) {
	if _, loaded := activeP2P.LoadOrStore(offer.ID, true); loaded {
		return
	}
	// Stand by on the outbound HTTPS relay while ICE attempts the preferred
	// direct path. The relay carries the same inner mTLS stream and therefore
	// cannot decrypt filenames, grants, metadata, or file contents.
	go acceptHomeRelay(offer.ID)
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
			proxyDetachedChannel(&homeP2PConn{ReadWriteCloser: rwc, pc: pc})
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
			_ = pc.Close()
			return fallbackNodeRelay(created.SessionID, errors.New(result.Error))
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
				_ = pc.Close()
				return fallbackNodeRelay(created.SessionID, err)
			case <-time.After(25 * time.Second):
				_ = pc.Close()
				return fallbackNodeRelay(created.SessionID, errors.New("no direct peer P2P path through ICE/STUN"))
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
