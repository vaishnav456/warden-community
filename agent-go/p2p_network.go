package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	nat "github.com/netbirdio/go-nat"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

var (
	agentP2PAPIOnce sync.Once
	agentP2PAPI     *webrtc.API
	agentP2PAPIErr  error
)

// sharedAgentP2PAPI keeps one UDP socket alive for every Warden Home session.
// A stable source port makes ICE hole punching and NAT keepalive effective and
// lets PCP/NAT-PMP/UPnP create a mapping without any router configuration.
func sharedAgentP2PAPI() (*webrtc.API, error) {
	agentP2PAPIOnce.Do(func() {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP: net.IPv4zero, Port: int(agentP2PUDPMin),
		})
		if err != nil {
			agentP2PAPIErr = fmt.Errorf("listen on direct P2P UDP port %d: %w", agentP2PUDPMin, err)
			return
		}
		mux := ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: conn})
		setting, err := homeP2PSettings(mux)
		if err != nil {
			_ = mux.Close()
			agentP2PAPIErr = err
			return
		}
		agentP2PAPI = webrtc.NewAPI(webrtc.WithSettingEngine(setting))
		go maintainP2PNATMapping(int(agentP2PUDPMin), "Warden Endpoint")
	})
	return agentP2PAPI, agentP2PAPIErr
}

func homeP2PSettings(mux ice.UDPMux) (webrtc.SettingEngine, error) {
	setting := webrtc.SettingEngine{}
	setting.DetachDataChannels()
	setting.EnableDataChannelBlockWrite(true)
	setting.SetICEUDPMux(mux)
	// Pion's WebRTC API multiplexes host candidates only. STUN candidates
	// use separate sockets, which must stay inside our firewall allowance.
	err := setting.SetEphemeralUDPPortRange(agentP2PUDPMin+1, agentP2PUDPMax)
	setting.SetICETimeouts(15*time.Second, 30*time.Second, 10*time.Second)
	return setting, err
}

func maintainP2PNATMapping(port int, description string) {
	const (
		lease      = 2 * time.Hour
		renewAfter = 60 * time.Minute
		retryAfter = 5 * time.Minute
	)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		gateway, err := nat.DiscoverGateway(ctx)
		cancel()
		if err != nil {
			log.Printf("P2P automatic NAT mapping unavailable (ICE/STUN remains active): %v", err)
			time.Sleep(retryAfter)
			continue
		}
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
		externalPort, err := gateway.AddPortMapping(ctx, "udp", port, description, lease)
		cancel()
		if err != nil {
			log.Printf("P2P automatic NAT mapping failed via %s (ICE/STUN remains active): %v", gateway.Type(), err)
			time.Sleep(retryAfter)
			continue
		}
		if externalIP, ipErr := gateway.GetExternalAddress(); ipErr == nil {
			log.Printf("P2P automatic NAT mapping active via %s: %s:%d -> UDP %d", gateway.Type(), externalIP, externalPort, port)
		} else {
			log.Printf("P2P automatic NAT mapping active via %s: external UDP %d -> %d", gateway.Type(), externalPort, port)
		}
		time.Sleep(renewAfter)
	}
}
