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
	"sync"
	"time"

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
			return fail(errors.New(message))
		}
		if answer, _ := result["answer_sdp"].(string); status == "answered" && answer != "" {
			if err = pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
				return fail(fmt.Errorf("apply P2P answer: %w", err))
			}
			select {
			case rwc := <-ready:
				return &homeP2PConn{ReadWriteCloser: rwc, pc: pc}, nil
			case err := <-failed:
				return fail(err)
			case <-time.After(25 * time.Second):
				return fail(errors.New("no direct P2P path; check UDP/STUN access or use another node mode"))
			}
		}
		time.Sleep(750 * time.Millisecond)
	}
	return fail(errors.New("Home Node did not answer the P2P offer"))
}
