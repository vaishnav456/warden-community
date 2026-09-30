package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/pion/webrtc/v4"
)

func TestHomeP2PHTTPReconnectAndCertificateValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "file contents")
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var dials atomic.Int32
	transport := newHomeP2PTLSTransport(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, func() (net.Conn, error) {
		dials.Add(1)
		return net.Dial("tcp", server.Listener.Addr().String())
	})
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "file contents" {
			t.Fatalf("request %d body %q: %v", i, body, err)
		}
	}
	if dials.Load() != 3 {
		t.Fatalf("wanted three independent tunnels, got %d", dials.Load())
	}
	if response, err := client.Get("https://wrong-node.invalid/v1/file"); err == nil {
		response.Body.Close()
		t.Fatal("accepted a certificate for the wrong node hostname")
	}
}

func TestHomeRelayCleanCloseIsNotSuccessfulEOF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("partial file"))
		_ = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}))
	defer server.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	data, err := io.ReadAll(&homeRelayConn{ws: ws})
	if string(data) != "partial file" {
		t.Fatalf("unexpected bytes %q", data)
	}
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("premature relay close reported success: %v", err)
	}
}

func TestHomeRelayStandbyDoesNotStartTLSHandshakeTimeout(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "delayed relay file")
	}))
	server.Config.ReadHeaderTimeout = 50 * time.Millisecond
	server.StartTLS()
	defer server.Close()
	initiator, target := net.Pipe()
	defer initiator.Close()
	defer target.Close()
	var dials atomic.Int32
	proxyHomeStream(target, func() (net.Conn, error) {
		dials.Add(1)
		return net.Dial("tcp", server.Listener.Addr().String())
	})
	// Standby lasts longer than the TLS server's handshake deadline.
	time.Sleep(150 * time.Millisecond)
	if dials.Load() != 0 {
		t.Fatal("relay standby started the local TLS handshake before the initiator arrived")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := newHomeP2PTLSTransport(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, func() (net.Conn, error) {
		return initiator, nil
	})
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("delayed relay handshake: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "delayed relay file" {
		t.Fatalf("delayed relay body %q: %v", body, err)
	}
}

func TestHomeP2PDeadlinesReachDetachedStream(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := &homeP2PConn{ReadWriteCloser: left}
	if err := conn.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("read ignored deadline")
	}
	if _, err := conn.Write([]byte("blocked")); err == nil {
		t.Fatal("write ignored deadline")
	}
}

type homePacketReader struct{ packet []byte }

func (p *homePacketReader) Read(buf []byte) (int, error) {
	if len(p.packet) == 0 {
		return 0, io.EOF
	}
	if len(buf) < len(p.packet) {
		return 0, io.ErrShortBuffer
	}
	n := copy(buf, p.packet)
	p.packet = nil
	return n, nil
}
func (p *homePacketReader) Write(buf []byte) (int, error) { return len(buf), nil }
func (p *homePacketReader) Close() error                  { return nil }

func TestHomeP2PPreservesMessageAcrossSmallStreamReads(t *testing.T) {
	packet := bytes.Repeat([]byte("x"), 48*1024)
	conn := &homeP2PConn{ReadWriteCloser: &homePacketReader{packet: packet}}
	var out bytes.Buffer
	if _, err := io.Copy(&out, conn); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), packet) {
		t.Fatalf("stream truncated: %d bytes", out.Len())
	}
}

// A local STUN responder proves that actual srflx sockets, not merely the
// shared host socket, use the ports allowed by the Windows firewall.
func TestHomeP2PSTUNCandidatesStayInsideFirewallRange(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ports := make(chan int, 8)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			request := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if request.Decode() != nil {
				continue
			}
			response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
				&stun.XORMappedAddress{IP: net.IPv4(203, 0, 113, 10), Port: addr.Port})
			if err != nil {
				continue
			}
			select {
			case ports <- addr.Port:
			default:
			}
			_, _ = server.WriteToUDP(response.Raw, addr)
		}
	}()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	mux := ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: socket})
	defer mux.Close()
	settings, err := homeP2PSettings(mux)
	if err != nil {
		t.Fatal(err)
	}
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{{URLs: []string{"stun:" + server.LocalAddr().String()}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err = pc.CreateDataChannel("test", nil); err != nil {
		t.Fatal(err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gathered:
	case <-time.After(5 * time.Second):
		t.Fatal("STUN gathering timed out")
	}
	var sourcePort int
	select {
	case sourcePort = <-ports:
	default:
		t.Fatal("no STUN packet received")
	}
	if sourcePort < int(homeP2PUDPMin)+1 || sourcePort > int(homeP2PUDPMax) {
		t.Fatalf("STUN socket %d outside firewall range", sourcePort)
	}
	expected := fmt.Sprintf("203.0.113.10 %d typ srflx", sourcePort)
	if !strings.Contains(pc.LocalDescription().SDP, expected) {
		t.Fatalf("no server reflexive candidate %q", expected)
	}
}
