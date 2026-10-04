package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var packetCaptureMu sync.Mutex

// capturePackets creates a tightly bounded PCAPNG capture using Pktmon, the
// packet monitor already shipped with supported Windows releases.  Keeping the
// orchestration here means Warden still ships one agent executable and no
// unsigned capture driver.  Captures are deliberately capped at 8 MiB because
// they use the same authenticated, tenant-scoped result channel as FILE_PULL.
func capturePackets(jobID string, p map[string]interface{}, log logFn) (int, string, error) {
	if !packetCaptureMu.TryLock() {
		return 1, "", fmt.Errorf("another Warden packet capture is already running")
	}
	defer packetCaptureMu.Unlock()

	duration := 30
	maxSizeMB := 4
	port := 0
	if value, ok := p["duration_seconds"].(float64); ok {
		duration = int(value)
	}
	if value, ok := p["max_size_mb"].(float64); ok {
		maxSizeMB = int(value)
	}
	if value, ok := p["port"].(float64); ok {
		port = int(value)
	}
	protocol, _ := p["protocol"].(string)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "any"
	}
	remoteIP, _ := p["remote_ip"].(string)
	remoteIP = strings.TrimSpace(remoteIP)
	if duration < 5 || duration > 120 || maxSizeMB < 1 || maxSizeMB > 8 || port < 0 || port > 65535 {
		return 1, "", fmt.Errorf("invalid packet capture limits")
	}
	if protocol != "any" && protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return 1, "", fmt.Errorf("invalid packet capture protocol")
	}
	if remoteIP != "" {
		if strings.Contains(remoteIP, "/") {
			if _, _, err := net.ParseCIDR(remoteIP); err != nil {
				return 1, "", fmt.Errorf("invalid remote IP or CIDR")
			}
		} else if net.ParseIP(remoteIP) == nil {
			return 1, "", fmt.Errorf("invalid remote IP or CIDR")
		}
	}
	if _, err := exec.LookPath("pktmon.exe"); err != nil {
		return 1, "", fmt.Errorf("Windows Packet Monitor is unavailable: %w", err)
	}
	// Pktmon owns one machine-wide ETW session and one shared filter list. Never
	// stop or overwrite a capture/filter configured by an administrator or
	// another diagnostic product. logman gives us a locale-independent exit
	// status for the named PktMon ETW session.
	if err := exec.Command("logman.exe", "query", "PktMon", "-ets").Run(); err == nil {
		return 1, "", fmt.Errorf("Windows Packet Monitor is already in use")
	}
	filterList, filterErr := boundedCombinedOutput(exec.Command("pktmon.exe", "filter", "list"))
	if filterErr != nil {
		return 1, "", fmt.Errorf("inspect packet capture filters: %w", filterErr)
	}
	if !strings.Contains(strings.ToLower(string(filterList)), "none") {
		return 1, "", fmt.Errorf("Windows Packet Monitor has existing filters; clear them before starting a Warden capture")
	}

	stageDir, err := jobStageDir(jobID)
	if err != nil {
		return 1, "", err
	}
	if err := createSystemOnlyDirectory(stageDir); err != nil {
		return 1, "", fmt.Errorf("secure capture staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)
	etlPath := filepath.Join(stageDir, "capture.etl")
	pcapPath := filepath.Join(stageDir, "capture.pcapng")

	// We verified above that the global Pktmon session is idle and its filter
	// list is empty, so cleanup below removes only the filter created here.
	defer exec.Command("pktmon.exe", "filter", "remove").Run()
	filterArgs := []string{"filter", "add", "WardenCapture"}
	if remoteIP != "" {
		filterArgs = append(filterArgs, "-i", remoteIP)
	}
	if port > 0 {
		filterArgs = append(filterArgs, "-p", strconv.Itoa(port))
	}
	if protocol != "any" {
		filterArgs = append(filterArgs, "-t", strings.ToUpper(protocol))
	}
	if len(filterArgs) > 3 {
		if out, filterErr := boundedCombinedOutput(exec.Command("pktmon.exe", filterArgs...)); filterErr != nil {
			return 1, "", fmt.Errorf("configure packet capture filter: %w (%s)", filterErr, strings.TrimSpace(string(out)))
		}
	}
	startArgs := []string{"start", "--capture", "--pkt-size", "0", "--file-name", etlPath, "--file-size", strconv.Itoa(maxSizeMB)}
	if out, startErr := boundedCombinedOutput(exec.Command("pktmon.exe", startArgs...)); startErr != nil {
		return 1, "", fmt.Errorf("start packet capture: %w (%s)", startErr, strings.TrimSpace(string(out)))
	}
	defer exec.Command("pktmon.exe", "stop").Run()
	log(fmt.Sprintf("Packet capture started for %d seconds (maximum %d MiB)", duration, maxSizeMB))
	time.Sleep(time.Duration(duration) * time.Second)
	if out, stopErr := boundedCombinedOutput(exec.Command("pktmon.exe", "stop")); stopErr != nil {
		return 1, "", fmt.Errorf("stop packet capture: %w (%s)", stopErr, strings.TrimSpace(string(out)))
	}
	if out, convertErr := boundedCombinedOutput(exec.Command("pktmon.exe", "etl2pcap", etlPath, "--out", pcapPath)); convertErr != nil {
		return 1, "", fmt.Errorf("convert capture to PCAPNG: %w (%s)", convertErr, strings.TrimSpace(string(out)))
	}
	content, err := os.ReadFile(pcapPath)
	if err != nil {
		return 1, "", fmt.Errorf("read PCAPNG capture: %w", err)
	}
	if len(content) == 0 || len(content) > maxRemoteTransferBytes {
		return 1, "", fmt.Errorf("capture size %d is outside the 1 byte to 8 MiB delivery limit", len(content))
	}
	if len(content) < 4 || !bytes.Equal(content[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		return 1, "", fmt.Errorf("converted capture is not a valid PCAPNG stream")
	}
	downloadName := fmt.Sprintf("warden-capture-%s.pcapng", time.Now().UTC().Format("20060102-150405"))
	if _, err := apiPostAuth("/api/agent/file-content", map[string]interface{}{
		"job_id": jobID, "path": pcapPath, "download_name": downloadName,
		"content_b64": base64.StdEncoding.EncodeToString(content), "size_bytes": len(content),
	}); err != nil {
		return 1, "", fmt.Errorf("upload packet capture: %w", err)
	}
	return 0, fmt.Sprintf("Captured %d bytes to %s", len(content), downloadName), nil
}

func getEventLogs(jobID string, p map[string]interface{}) (int, string, error) {
	logName, _ := p["log_name"].(string)
	if logName == "" {
		logName = "System"
	}
	if logName != "System" && logName != "Application" && logName != "Security" {
		return 1, "", fmt.Errorf("log_name must be System, Application, or Security")
	}
	maxEvents := 50
	if m, ok := p["max_events"].(float64); ok && m > 0 {
		if int(m) <= 500 {
			maxEvents = int(m)
		} else {
			maxEvents = 500
		}
	}
	hours := 24
	if h, ok := p["hours"].(float64); ok && h > 0 {
		if int(h) <= 168 {
			hours = int(h)
		} else {
			hours = 168
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NonInteractive", "-Command",
		fmt.Sprintf(
			"Get-WinEvent -LogName %s -MaxEvents %d | Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-%d)} | Select-Object TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Json -Compress",
			logName, maxEvents, hours,
		))
	out, cmdErr := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return 1, "", fmt.Errorf("Get-WinEvent timed out after 45 seconds")
	}
	eventsJSON := strings.TrimSpace(string(out))
	if eventsJSON == "" {
		if cmdErr != nil {
			return 1, "", fmt.Errorf("Get-WinEvent: %w", cmdErr)
		}
		eventsJSON = "[]"
	}
	// The events only ever exist in this POST -- log_output below is just a
	// summary sentence, not the actual event data. Discarding this error
	// used to mean a failed delivery still reported job success with a
	// plausible-looking message, silently losing the collected events.
	if _, err := apiPostAuth("/api/agent/event-logs", map[string]interface{}{
		"job_id":      jobID,
		"log_name":    logName,
		"events_json": eventsJSON,
	}); err != nil {
		return 1, "", fmt.Errorf("report event logs: %w", err)
	}
	return 0, fmt.Sprintf("Collected event log entries from %s", logName), nil
}

func collectNetworkFlows() (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// Bounded connection snapshots provide process-aware analysis without
	// retaining payloads. Future WFP rule-hit telemetry uses the same API.
	script := `$ErrorActionPreference='SilentlyContinue'; ` +
		`$items=@(); Get-NetTCPConnection | Select-Object -First 750 | ForEach-Object { ` +
		`$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; ` +
		`$items += [pscustomobject]@{protocol='tcp';direction='outbound';local_address=$_.LocalAddress;local_port=$_.LocalPort;remote_address=$_.RemoteAddress;remote_port=$_.RemotePort;process_id=$_.OwningProcess;process_name=$p.ProcessName;process_path=$p.Path;state=[string]$_.State} }; ` +
		`Get-NetUDPEndpoint | Select-Object -First 250 | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; ` +
		`$items += [pscustomobject]@{protocol='udp';direction='outbound';local_address=$_.LocalAddress;local_port=$_.LocalPort;remote_address=$null;remote_port=$null;process_id=$_.OwningProcess;process_name=$p.ProcessName;process_path=$p.Path;state='Listening'} }; ` +
		`ConvertTo-Json -InputObject $items -Compress -Depth 4`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if ctx.Err() != nil {
		return 1, "", fmt.Errorf("collect network flows: timed out")
	}
	if err != nil {
		return commandExitCode(err), string(out), fmt.Errorf("collect network flows: %w", err)
	}
	var flows []map[string]interface{}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) > 0 && string(trimmed) != "null" {
		if err := json.Unmarshal(trimmed, &flows); err != nil {
			return 1, "", fmt.Errorf("decode network flows: %w", err)
		}
	}
	if len(flows) > 1000 {
		flows = flows[:1000]
	}
	if _, err := apiPostAuth("/api/agent/network-flows", map[string]interface{}{"flows": flows}); err != nil {
		return 1, "", fmt.Errorf("report network flows: %w", err)
	}
	return 0, fmt.Sprintf("Reported %d network flow observations", len(flows)), nil
}
