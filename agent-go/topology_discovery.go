package main

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var topologyCache struct {
	sync.Mutex
	at   time.Time
	data map[string]interface{}
}

// topologyTelemetry returns a bounded, metadata-only LAN snapshot. It never
// captures packet contents or credentials. Results are cached because neighbor
// and LLDP tools can briefly touch the network stack on busy machines.
func topologyTelemetry() map[string]interface{} {
	topologyCache.Lock()
	defer topologyCache.Unlock()
	if topologyCache.data != nil && time.Since(topologyCache.at) < 5*time.Minute {
		return topologyCache.data
	}
	data := map[string]interface{}{
		"captured_at": time.Now().UTC().Format(time.RFC3339),
		"collector":   "interface-neighbor-v1",
		"interfaces":  localInterfaceInventory(),
	}
	if runtime.GOOS == "windows" {
		collectWindowsTopology(data)
	} else {
		collectUnixTopology(data)
	}
	topologyCache.data, topologyCache.at = data, time.Now()
	return data
}

func localInterfaceInventory() []map[string]interface{} {
	result := []map[string]interface{}{}
	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagUp == 0 || item.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := item.Addrs()
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.String())
		}
		result = append(result, map[string]interface{}{
			"name": item.Name, "index": item.Index, "mac": item.HardwareAddr.String(),
			"mtu": item.MTU, "addresses": values,
		})
		if len(result) >= 32 {
			break
		}
	}
	return result
}

func commandJSON(name string, args ...string) interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	out, err := command.Output()
	if err != nil || len(out) > 512*1024 {
		return nil
	}
	var value interface{}
	if json.Unmarshal(out, &value) != nil {
		return nil
	}
	return value
}

func collectWindowsTopology(data map[string]interface{}) {
	script := `$ErrorActionPreference='SilentlyContinue'; [pscustomobject]@{` +
		`neighbors=@(Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.State -in @('Reachable','Stale','Delay','Probe','Permanent')} | Select-Object -First 256 @{n='ip';e={$_.IPAddress}},@{n='mac';e={$_.LinkLayerAddress}},@{n='interface';e={$_.InterfaceAlias}},@{n='state';e={[string]$_.State}},@{n='source';e={'arp-ndp'}});` +
		`gateways=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 8 @{n='ip';e={$_.NextHop}},@{n='interface_index';e={$_.InterfaceIndex}},@{n='metric';e={$_.RouteMetric}});` +
		`adapters=@(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 32 Name,MacAddress,LinkSpeed,ifIndex)` +
		`} | ConvertTo-Json -Compress -Depth 5`
	if value := commandJSON("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script); value != nil {
		if object, ok := value.(map[string]interface{}); ok {
			for key, item := range object {
				data[strings.ToLower(key)] = item
			}
			if gateways, ok := data["gateways"].([]interface{}); ok && len(gateways) > 0 {
				if gateway, ok := gateways[0].(map[string]interface{}); ok {
					ip := strings.TrimSpace(stringValue(gateway["ip"]))
					if ip != "" {
						pingScript := `$s=@(Test-Connection -ComputerName '` + strings.ReplaceAll(ip, "'", "") + `' -Count 2 -ErrorAction SilentlyContinue); [pscustomobject]@{latency_ms=$(if($s.Count){[math]::Round(($s|Measure-Object ResponseTime -Average).Average,2)}else{$null});packet_loss_pct=[math]::Round((2-$s.Count)*50,1)} | ConvertTo-Json -Compress`
						if measured, ok := commandJSON("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", pingScript).(map[string]interface{}); ok {
							gateway["latency_ms"] = measured["latency_ms"]
							gateway["packet_loss_pct"] = measured["packet_loss_pct"]
						}
					}
				}
			}
		}
	}
}

func stringValue(value interface{}) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func collectUnixTopology(data map[string]interface{}) {
	if value := commandJSON("ip", "-j", "neigh", "show"); value != nil {
		data["neighbors"] = value
	}
	if value := commandJSON("ip", "-j", "route", "show", "default"); value != nil {
		data["gateways"] = value
	}
	// lldpd understands LLDP and, when enabled locally, CDP/FDP/EDP. Absence
	// of lldpcli is reported honestly by omitting this field.
	command := exec.Command("lldpcli", "-f", "json", "show", "neighbors", "details")
	if out, err := command.Output(); err == nil && len(out) <= 512*1024 {
		var value interface{}
		if json.Unmarshal(out, &value) == nil {
			data["lldp_cdp"] = value
			data["discovery_protocols"] = []string{"lldp", "cdp"}
		}
	}
}
