package main

// Direct-only WebRTC transport for Warden Home. Warden exchanges short-lived
// SDP metadata, but the resulting data channel runs endpoint-to-node. The
// existing HTTPS+mTLS stream is carried inside it, so grants and certificate
// identity checks remain unchanged.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

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
func (c *homeP2PConn) LocalAddr() net.Addr              { return homeP2PAddr("endpoint") }
func (c *homeP2PConn) RemoteAddr() net.Addr             { return homeP2PAddr("home-node") }
func (c *homeP2PConn) SetDeadline(time.Time) error      { return nil }
func (c *homeP2PConn) SetReadDeadline(time.Time) error  { return nil }
func (c *homeP2PConn) SetWriteDeadline(time.Time) error { return nil }

type homeP2PAddr string

const (
	agentP2PUDPMin uint16 = 55100
)

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

func (c *homeRelayConn) Close() error                       { return c.ws.Close() }
func (c *homeRelayConn) LocalAddr() net.Addr                { return homeP2PAddr("endpoint-relay") }
func (c *homeRelayConn) RemoteAddr() net.Addr               { return homeP2PAddr("home-node-relay") }
func (c *homeRelayConn) SetDeadline(t time.Time) error      { return nil }
func (c *homeRelayConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *homeRelayConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

func dialHomeRelay(sessionID string) (net.Conn, error) {
	base, err := url.Parse(serverURL())
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, errors.New("invalid Warden relay URL")
	}
	if base.Scheme == "https" {
		base.Scheme = "wss"
	} else {
		base.Scheme = "ws"
	}
	base.Path = "/home-relay/endpoint/" + url.PathEscape(sessionID)
	base.RawQuery = ""
	headers := http.Header{}
	headers.Set("X-Agent-Key", apiKey)
	dialer := websocket.Dialer{HandshakeTimeout: 30 * time.Second, Proxy: http.ProxyFromEnvironment}
	if httpClient != nil {
		if transport, ok := httpClient.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil {
			dialer.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
	}
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

func fallbackHomeRelay(sessionID string, directErr error) (net.Conn, error) {
	conn, relayErr := dialHomeRelay(sessionID)
	if relayErr == nil {
		logInfo("Warden Home direct P2P unavailable; using end-to-end encrypted HTTPS relay")
		return conn, nil
	}
	return nil, fmt.Errorf("direct P2P failed (%v); HTTPS relay failed (%v)", directErr, relayErr)
}

func dialHomeP2P(username string, node homeNode) (net.Conn, error) {
	api, err := sharedAgentP2PAPI()
	if err != nil {
		return nil, err
	}
	ice := []webrtc.ICEServer{}
	if len(node.STUNURLs) > 0 {
		ice = append(ice, webrtc.ICEServer{URLs: node.STUNURLs})
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
	created, err := apiPost("/api/agent/home-p2p/offer", map[string]interface{}{
		"username": username, "node_id": node.ID, "offer_sdp": local.SDP,
	}, true, 30)
	if err != nil {
		return fail(fmt.Errorf("publish P2P offer: %w", err))
	}
	sessionID, _ := created["session_id"].(string)
	if sessionID == "" {
		return fail(errors.New("Warden returned no P2P session"))
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		result, pollErr := apiPost("/api/agent/home-p2p/answer", map[string]interface{}{
			"session_id": sessionID,
		}, true, 15)
		if pollErr != nil {
			return fail(fmt.Errorf("poll P2P answer: %w", pollErr))
		}
		status, _ := result["status"].(string)
		if status == "failed" {
			message, _ := result["error"].(string)
			if message == "" {
				message = "Home Node rejected P2P negotiation"
			}
			_ = pc.Close()
			return fallbackHomeRelay(sessionID, errors.New(message))
		}
		if answer, _ := result["answer_sdp"].(string); status == "answered" && answer != "" {
			if err = pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
				return fail(fmt.Errorf("apply P2P answer: %w", err))
			}
			select {
			case rwc := <-ready:
				return &homeP2PConn{ReadWriteCloser: rwc, pc: pc}, nil
			case err := <-failed:
				_ = pc.Close()
				return fallbackHomeRelay(sessionID, err)
			case <-time.After(25 * time.Second):
				_ = pc.Close()
				return fallbackHomeRelay(sessionID, errors.New("no direct P2P path through ICE/STUN"))
			}
		}
		time.Sleep(750 * time.Millisecond)
	}
	return fail(errors.New("Home Node did not answer the P2P offer"))
}
