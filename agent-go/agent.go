package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cpuPkg "github.com/shirou/gopsutil/v3/cpu"
	diskPkg "github.com/shirou/gopsutil/v3/disk"
	memPkg "github.com/shirou/gopsutil/v3/mem"
	netPkg "github.com/shirou/gopsutil/v3/net"
	procPkg "github.com/shirou/gopsutil/v3/process"

	"golang.org/x/sys/windows/registry"
)

var (
	agentStartTime         = time.Now()
	lastNetCounters        *netPkg.IOCountersStat
	lastNetTime            time.Time
	netMu                  sync.Mutex
	policyInventoryMu      sync.Mutex
	pendingPolicyInventory map[string]interface{}
	policyInventoryReady   bool
	lastTamperRepair       time.Time
	deviceTypeOnce         sync.Once
	cachedDeviceType       = "unknown"
	selfRemovalScheduled   atomic.Bool
)

// runAgent is the main agent loop, called from both standalone and service modes.
// stopCh is closed when shutdown is requested; nil means run until killed.
func runAgent(stopCh <-chan struct{}) {
	initLogging()
	ensureDirs()
	// Certificate validation depends on a sane local clock. Ask the operating
	// system's configured time service to synchronize before enrollment, then
	// refine small drift from Warden's authenticated heartbeat timestamp.
	if err := prepareSystemClock(); err != nil {
		logWarn("Initial operating-system time synchronization was deferred: %v", err)
	}
	if err := recoverPendingEnrollment(); err != nil {
		logError("Could not recover pending enrollment: %v", err)
		return
	}

	if err := seedBuildConfig(); err != nil {
		logError("Could not seed build-pinned configuration: %v", err)
		return
	}
	_ = loadConfig()

	if !isEnrolled() {
		// The build-service packages a bootstrap config.json containing
		// enrollment_token (see build-service/builder.py,
		// routes/endpoints.py:generate_installer) — that's the normal
		// source for a shipped installer. WARDEN_ENROLLMENT_TOKEN remains
		// supported as an explicit override for manual/dev enrollment.
		token := os.Getenv("WARDEN_ENROLLMENT_TOKEN")
		if token == "" {
			token = getConfig().EnrollmentToken
		}
		if token == "" {
			logError("Agent is not enrolled, and no enrollment token was found " +
				"(neither WARDEN_ENROLLMENT_TOKEN env var nor enrollment_token in config.json).")
			os.Exit(1)
		}
		if err := doEnroll(token); err != nil {
			logError("Enrollment failed: %v", err)
			os.Exit(1)
		}
	}

	key, err := loadAPIKey()
	if err != nil {
		logError("Failed to load API key: %v", err)
		os.Exit(1)
	}

	if err := loadConfig(); err != nil {
		logError("Failed to load config: %v", err)
		os.Exit(1)
	}

	c := getConfig()
	revokeExpiredElevations()
	if err := initReplayStore(); err != nil {
		logError("Failed to initialize durable replay protection: %v", err)
		return
	}
	if err := initComms(key, effectiveCertFingerprints(c), c.TLSTrustMode); err != nil {
		logError("Failed to initialize secure communications: %v", err)
		return
	}
	// A self-update does not run the interactive `install` command. Repair the
	// build-pinned Credential Provider here before declaring the replacement
	// healthy, so an updater can roll back atomically if its signed companion
	// DLL is missing, corrupted, or cannot be registered.
	if err := ensureCredentialProviderInstalled(); err != nil {
		logError("Credential Provider startup repair failed: %v", err)
		return
	}
	applyTamperProtection()
	if err := ensureControlPlaneFirewallRule(); err != nil {
		logWarn("Could not ensure control-plane firewall rule: %v", err)
	}
	lastTamperRepair = time.Now()
	go runIdentityBroker(stopCh)
	go runSupportBroker(stopCh)
	go ensureSupportShortcut()

	// Inventory the effective, configured machine policies in the background.
	// The first heartbeat is not delayed; once collection finishes, the next
	// successful heartbeat delivers the snapshot and clears it locally.
	go func() {
		inventory := collectConfiguredPolicyValues()
		policyInventoryMu.Lock()
		pendingPolicyInventory = inventory
		policyInventoryReady = true
		policyInventoryMu.Unlock()
	}()

	pubKey, err := loadServerPubkey(c.ServerEd25519Pubkey)
	if err != nil {
		logError("Invalid server public key: %v", err)
		os.Exit(1)
	}
	// update.bat treats this marker as proof that the replacement binary made
	// it through configuration, replay-store, TLS and signing-key startup.
	// If it never appears, the independent updater restores the prior binary.
	if err := os.WriteFile(updateHealthPath, []byte(agentVersion), 0600); err != nil {
		logWarn("Could not write update health marker: %v", err)
	}

	logInfo("Warden Agent %s started — polling every %ds", agentVersion, pollIntervalSec)
	jobQueue := make(chan json.RawMessage, 1)
	var jobWorkerBusy atomic.Bool
	go func() {
		for rawJob := range jobQueue {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						logError("Recovered panic in job worker: %v", recovered)
					}
				}()
				processJob(rawJob, pubKey)
			}()
			jobWorkerBusy.Store(false)
		}
	}()

	ticker := time.NewTicker(pollIntervalSec * time.Second)
	defer ticker.Stop()

	// Run once immediately
	runHeartbeatCycle(jobQueue, &jobWorkerBusy)

	for {
		select {
		case <-ticker.C:
			runHeartbeatCycle(jobQueue, &jobWorkerBusy)
		case <-stopCh:
			logInfo("Stop signal received — shutting down")
			close(jobQueue)
			return
		}
	}
}

func runHeartbeatCycle(jobQueue chan<- json.RawMessage, jobWorkerBusy *atomic.Bool) {
	// Hardware probes and platform APIs are outside our control. A driver or
	// library panic must fail one poll, not terminate the Windows service.
	defer func() {
		if recovered := recover(); recovered != nil {
			logError("Recovered panic in heartbeat cycle: %v", recovered)
		}
	}()
	revokeExpiredElevations()
	if clientCertificateNeedsRenewal(48 * time.Hour) {
		if err := renewDeviceCertificate(); err != nil {
			logWarn("Device certificate renewal deferred: %v", err)
		}
	}
	if !selfRemovalScheduled.Load() && time.Since(lastTamperRepair) >= 5*time.Minute {
		applyTamperProtection()
		lastTamperRepair = time.Now()
	}
	// Nonce cleanup on every cycle
	cleanupExpiredNonces()
	flushPendingJobResults()

	capacity := 0
	if !jobWorkerBusy.Load() && len(jobQueue) == 0 {
		capacity = 1
	}
	jobs, err := postHeartbeat(capacity)
	if err != nil {
		logWarn("Heartbeat failed: %v", err)
		return
	}

	for _, rawJob := range jobs {
		// Reserve the only worker slot before publishing to the channel. This
		// closes the tiny receive/store race where a heartbeat could observe an
		// empty channel before the worker had marked itself busy.
		jobWorkerBusy.Store(true)
		select {
		case jobQueue <- rawJob:
		default:
			jobWorkerBusy.Store(false)
			// The database lease expires, so a saturated local queue is retried
			// safely later instead of growing without bound.
			logWarn("Job queue full; leased command will be retried after lease expiry")
		}
	}
}

func renewDeviceCertificate() error {
	c := getConfig()
	csr, err := csrFromStoredClientKey(c.EndpointID)
	var newKeyPEM []byte
	if err != nil {
		// Agents installed before device certificates existed have no local
		// key. Recover without reinstalling: create the key on this endpoint,
		// send only its CSR, and persist the key only after the CA responds.
		newKeyPEM, csr, err = generateCSR(c.EndpointID)
		if err != nil {
			return fmt.Errorf("generate replacement device identity: %w", err)
		}
	}
	result, err := apiPost("/api/agent/certificate/renew", map[string]interface{}{
		"csr_pem": string(csr),
	}, true, 30)
	if err != nil {
		return err
	}
	certificate, _ := result["client_cert_pem"].(string)
	if certificate == "" {
		return fmt.Errorf("renewal response has no certificate")
	}
	if len(newKeyPEM) > 0 {
		if err := saveClientKey(newKeyPEM); err != nil {
			return err
		}
	}
	if err := saveClientCert(certificate); err != nil {
		return err
	}
	reloadClientCertificate()
	logInfo("Device certificate renewed.")
	return nil
}

func flushPendingJobResults() {
	for jobID, result := range pendingJobReports() {
		if err := reportJobResult(
			jobID, result.Status, result.ExitCode, result.LogOutput, result.ErrorMsg,
		); err != nil {
			continue
		}
		if err := acknowledgeJobReport(jobID); err != nil {
			logWarn("Could not persist result acknowledgement for %s: %v", jobID, err)
		}
	}
}

func postHeartbeat(jobCapacity int) ([]json.RawMessage, error) {
	hostname, _ := os.Hostname()
	cpuPcts, _ := cpuPkg.Percent(time.Second, false)
	cpuPct := 0.0
	if len(cpuPcts) > 0 {
		cpuPct = cpuPcts[0]
	}

	vm, _ := memPkg.VirtualMemory()
	du, _ := diskPkg.Usage(`C:\`)

	// Network throughput delta
	netMu.Lock()
	counters, _ := netPkg.IOCounters(false)
	var sentMbps, recvMbps float64
	if len(counters) > 0 {
		now := time.Now()
		if lastNetCounters != nil && !lastNetTime.IsZero() {
			elapsed := now.Sub(lastNetTime).Seconds()
			if elapsed > 0 {
				sentMbps = float64(counters[0].BytesSent-lastNetCounters.BytesSent) / elapsed / 125000
				recvMbps = float64(counters[0].BytesRecv-lastNetCounters.BytesRecv) / elapsed / 125000
			}
		}
		c := counters[0]
		lastNetCounters = &c
		lastNetTime = now
	}
	netMu.Unlock()

	// Agent process memory
	var agentMemMB float64
	if proc, err := procPkg.NewProcess(int32(os.Getpid())); err == nil {
		if mi, err := proc.MemoryInfo(); err == nil {
			agentMemMB = float64(mi.RSS) / (1024 * 1024)
		}
	}

	ramPct := 0.0
	diskFreeGB := 0.0
	if vm != nil {
		ramPct = vm.UsedPercent
	}
	if du != nil {
		diskFreeGB = float64(du.Free) / (1024 * 1024 * 1024)
	}

	capabilities := make([]string, 0, len(operationWhitelist))
	for operation, enabled := range operationWhitelist {
		if enabled {
			capabilities = append(capabilities, operation)
		}
	}
	if credentialProviderInstalled() {
		capabilities = append(capabilities, "WARDEN_SIGNIN")
	}
	// Distinct from the legacy provisioning operation: servers use this to
	// avoid sending passwordless managed-shadow payloads to pre-2.5 agents.
	capabilities = append(capabilities, "WARDEN_SHADOW_CREDENTIAL")
	sort.Strings(capabilities)
	body := map[string]interface{}{
		"hostname":              hostname,
		"interactive_user":      currentInteractiveUser(),
		"managed_domain_suffix": currentManagedDNSSuffix(),
		"cpu_pct":               round2(cpuPct),
		"ram_used_pct":          round2(ramPct),
		"disk_free_gb":          round2(diskFreeGB),
		"agent_version":         agentVersion,
		"net_sent_mbps":         round3(max64(sentMbps, 0)),
		"net_recv_mbps":         round3(max64(recvMbps, 0)),
		"agent_memory_mb":       round1(agentMemMB),
		"agent_uptime_sec":      int(time.Since(agentStartTime).Seconds()),
		"job_capacity":          jobCapacity,
		"platform":              runtime.GOOS,
		"running_job_id":        activeAgentJobID(),
		"local_ip":              primaryLocalIPv4(),
		"device_type":           windowsDeviceType(),
		"topology_telemetry":    topologyTelemetry(),
		"capabilities":          capabilities,
		"capability_details": map[string]interface{}{
			"remote_control": "Native Windows desktop capture and input",
			"device_health":  deviceHealthSnapshot(),
		},
	}
	policyInventoryMu.Lock()
	inventory := pendingPolicyInventory
	inventoryReady := policyInventoryReady
	if inventoryReady {
		body["policy_inventory"] = inventory
	}
	policyInventoryMu.Unlock()
	rawResp, err := apiPostRaw(
		"/api/agent/heartbeat", body, true, heartbeatTimeoutSec,
	)
	if err != nil {
		return nil, err
	}
	if inventoryReady {
		policyInventoryMu.Lock()
		pendingPolicyInventory = nil
		policyInventoryReady = false
		policyInventoryMu.Unlock()
	}
	var resp struct {
		Commands       []json.RawMessage `json:"commands"`
		ServerTime     string            `json:"server_time"`
		BranchTimezone string            `json:"branch_timezone"`
	}
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return nil, fmt.Errorf("decode heartbeat response: %w", err)
	}
	reconcileEndpointClock(resp.ServerTime, resp.BranchTimezone)
	return resp.Commands, nil
}

func processJob(rawJSON []byte, pubKey ed25519.PublicKey) {
	var jobID string
	// Quick extract job_id for logging/reporting even before full parse
	var peek struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(rawJSON, &peek)
	jobID = peek.JobID

	report := func(status string, exitCode int, logOutput, errorMsg string) {
		if err := reportJobResult(jobID, status, exitCode, logOutput, errorMsg); err == nil {
			if ackErr := acknowledgeJobReport(jobID); ackErr != nil {
				logWarn("Could not persist result acknowledgement for %s: %v", jobID, ackErr)
			}
		}
	}

	env, err := verifyEnvelope(rawJSON, pubKey)
	if err != nil {
		logError("Job %s signature verification failed: %v", jobID, err)
		report("failed", -1, "", err.Error())
		return
	}

	if previous, ok := getCompletedJob(env.JobID); ok {
		logInfo("Job %s already completed locally; re-reporting result", env.JobID)
		report(
			previous.Status, previous.ExitCode, previous.LogOutput,
			previous.ErrorMsg,
		)
		return
	}

	if err := checkAndConsumeNonce(env.Nonce, env.ExpiresAt); err != nil {
		logError("Job %s replay detected: %v", env.JobID, err)
		report("failed", -2, "", err.Error())
		return
	}

	logCallback := func(line string) {
		appendJobLog(env.JobID, line)
	}

	setActiveAgentJobID(env.JobID)
	defer setActiveAgentJobID("")
	exitCode, logOutput, dispErr := safeDispatchJob(env, logCallback)
	logOutput = limitResultText(logOutput, 1024*1024, "job output")
	status := "completed"
	errorMsg := ""
	if dispErr != nil {
		logError("Job %s dispatch error: %v", env.JobID, dispErr)
		status = "failed"
		errorMsg = dispErr.Error()
		if exitCode == 0 {
			exitCode = 1
		}
	} else if exitCode != 0 {
		status = "failed"
	}
	errorMsg = limitResultText(errorMsg, 16*1024, "error message")
	result := completedJob{
		Status: status, ExitCode: exitCode, LogOutput: logOutput,
		ErrorMsg: errorMsg,
	}
	if err := recordCompletedJob(env.JobID, result); err != nil {
		logError("Could not persist result for job %s: %v", env.JobID, err)
		// The operation already happened. Preserve its truthful result on the
		// server and append the local durability warning instead of claiming a
		// successful reboot/elevation/etc. failed.
		warning := fmt.Sprintf("local replay-cache persistence failed: %v", err)
		if errorMsg != "" {
			errorMsg += "; " + warning
		} else {
			errorMsg = warning
		}
		report(status, exitCode, logOutput, errorMsg)
		return
	}
	report(status, exitCode, logOutput, errorMsg)
}

func limitResultText(value string, maxBytes int, label string) string {
	if len(value) <= maxBytes {
		return value
	}
	suffix := fmt.Sprintf("\n[Warden truncated %s after %d bytes]", label, maxBytes)
	keep := maxBytes - len(suffix)
	if keep < 0 {
		keep = 0
	}
	return value[:keep] + suffix
}

func safeDispatchJob(env *Envelope, log logFn) (exitCode int, output string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			exitCode = 1
			err = fmt.Errorf("job handler panic: %v", recovered)
			logError("Recovered panic in job %s (%s): %v", env.JobID, env.Operation, recovered)
		}
	}()
	return dispatchJob(env, log)
}

// doEnroll performs the one-time enrollment process.
func doEnroll(token string) error {
	logInfo("Starting enrollment with token %s...", token[:min(8, len(token))])

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	hardwareID := getHardwareID()
	deviceIdentity := collectDeviceIdentity(hardwareID)
	osInfo := collectOSInfo()

	keyPEM, csrPEM, err := generateCSR(hostname)
	if err != nil {
		return fmt.Errorf("generate mTLS CSR: %w", err)
	}

	pinned := getConfig()
	if pinned.InstallationID == "" {
		installationID, err := newInstallationID()
		if err != nil {
			return err
		}
		pinned.InstallationID = installationID
		if err := saveConfig(pinned); err != nil {
			return fmt.Errorf("persist installation identity: %w", err)
		}
	}
	if pinned.ServerEd25519Pubkey == "" || (normalizeTLSTrustMode(pinned.TLSTrustMode) != "webpki" && pinned.CertFingerprint == "") {
		return fmt.Errorf(
			"enrollment requires a build-provisioned signing key and TLS trust configuration",
		)
	}
	enrollmentNonce, err := newEnrollmentNonce()
	if err != nil {
		return err
	}

	resp, err := apiPostEnrollment("/enroll", map[string]interface{}{
		"token":            token,
		"hostname":         hostname,
		"hardware_id":      hardwareID,
		"device_identity":  deviceIdentity,
		"agent_version":    agentVersion,
		"os_info":          osInfo,
		"csr_pem":          string(csrPEM),
		"installation_id":  pinned.InstallationID,
		"enrollment_nonce": enrollmentNonce,
	}, pinned.CertFingerprint, pinned.TLSTrustMode, 30)
	if err != nil {
		return fmt.Errorf("enrollment POST failed: %w", err)
	}

	apiKey, _ := resp["api_key"].(string)
	if apiKey == "" {
		return fmt.Errorf("enrollment response missing api_key")
	}
	pubKey, _ := resp["server_ed25519_pubkey"].(string)
	if pubKey != pinned.ServerEd25519Pubkey {
		return fmt.Errorf("enrollment signing key does not match build pin")
	}
	if err := verifyEnrollmentResponse(resp, pinned.ServerEd25519Pubkey, enrollmentNonce); err != nil {
		return fmt.Errorf("verify enrollment response: %w", err)
	}

	serverURLVal := pinned.ServerURL
	if serverURLVal == "" {
		serverURLVal = os.Getenv("WARDEN_SERVER_URL")
	}
	if serverURLVal == "" {
		serverURLVal = "https://warden.example.com"
	}
	c := AgentConfig{
		ServerURL:           serverURLVal,
		ServerEd25519Pubkey: pinned.ServerEd25519Pubkey,
		CertFingerprint:     pinned.CertFingerprint,
		CertFingerprints:    effectiveCertFingerprints(pinned),
		TLSTrustMode:        normalizeTLSTrustMode(pinned.TLSTrustMode),
		InstallationID:      pinned.InstallationID,
		CompanyID:           strVal(resp["company_id"]),
		BranchID:            strVal(resp["branch_id"]),
		EndpointID:          strVal(resp["endpoint_id"]),
	}
	// mTLS material must be durable before the API credential/config commit.
	// Otherwise a disk/ACL failure here would leave isEnrolled() true while
	// every authenticated request is rejected for lacking the client cert.
	if clientCertPEM, _ := resp["client_cert_pem"].(string); clientCertPEM != "" {
		if err := saveClientKey(keyPEM); err != nil {
			return fmt.Errorf("save mTLS client key: %w", err)
		}
		if err := saveClientCert(clientCertPEM); err != nil {
			return fmt.Errorf("save mTLS client certificate: %w", err)
		}
		logInfo("mTLS client certificate issued and stored.")
	}
	if err := stagePendingEnrollment(c, apiKey); err != nil {
		return fmt.Errorf("stage enrollment credentials: %w", err)
	}
	if err := recoverPendingEnrollment(); err != nil {
		return fmt.Errorf("finalize enrollment credentials: %w", err)
	}

	logInfo("Enrollment successful. EndpointID: %s, hostname: %s", c.EndpointID, hostname)
	return nil
}

func newEnrollmentNonce() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate enrollment nonce: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func newInstallationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate installation identity: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func getHardwareID() string {
	return queryCIMValue("Win32_ComputerSystemProduct", "UUID")
}

// primaryLocalIPv4 reports the address that identifies this machine on its
// LAN.  It deliberately excludes loopback, APIPA and tunnel/down interfaces;
// the server separately records the transport address as last_seen_ip.
func primaryLocalIPv4() string {
	interfaces, err := netPkg.Interfaces()
	if err != nil {
		return ""
	}
	bestAddress, bestScore := "", 100
	for _, iface := range interfaces {
		flags := strings.ToLower(strings.Join(iface.Flags, " "))
		if !strings.Contains(flags, "up") || strings.Contains(flags, "loopback") {
			continue
		}
		name := strings.ToLower(iface.Name)
		adapterPenalty := 0
		if strings.Contains(name, "virtual") || strings.Contains(name, "vpn") ||
			strings.Contains(name, "tunnel") || strings.Contains(name, "loopback") {
			adapterPenalty = 20
		}
		for _, address := range iface.Addrs {
			ip, _, parseErr := net.ParseCIDR(address.Addr)
			if parseErr != nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				continue
			}
			score := adapterPenalty
			if !ip.IsPrivate() {
				score += 10
			}
			if score < bestScore {
				bestAddress, bestScore = ip.String(), score
			}
		}
	}
	return bestAddress
}

func windowsDeviceType() string {
	deviceTypeOnce.Do(func() {
		model := strings.ToLower(queryCIMValue("Win32_ComputerSystem", "Model"))
		pcType := strings.TrimSpace(queryCIMValue("Win32_ComputerSystem", "PCSystemType"))
		chassis := strings.Trim(queryCIMValue("Win32_SystemEnclosure", "ChassisTypes"), "{}[] ")
		switch {
		case strings.Contains(model, "raspberry") || strings.Contains(model, "iot") || pcType == "6":
			cachedDeviceType = "iot"
		case pcType == "2" || containsCSVValue(chassis, "8", "9", "10", "11", "12", "14", "18", "21", "30", "31", "32"):
			cachedDeviceType = "laptop"
		case pcType == "4" || pcType == "5" || pcType == "7" || pcType == "8" ||
			containsCSVValue(chassis, "23", "28"):
			cachedDeviceType = "server"
		default:
			cachedDeviceType = "desktop"
		}
	})
	return cachedDeviceType
}

func containsCSVValue(value string, candidates ...string) bool {
	normalized := strings.NewReplacer(";", ",", " ", ",").Replace(value)
	for _, part := range strings.Split(normalized, ",") {
		part = strings.TrimSpace(part)
		for _, candidate := range candidates {
			if part == candidate {
				return true
			}
		}
	}
	return false
}

func queryCIMValue(className, property string) string {
	// WMIC remains available on older Windows releases; PowerShell CIM is the
	// supported fallback on current Windows where WMIC is an optional feature.
	if out, err := exec.Command("wmic", "path", className, "get", property, "/value").Output(); err == nil {
		prefix := property + "="
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
				return strings.TrimSpace(line[len(prefix):])
			}
		}
	}
	command := fmt.Sprintf("(Get-CimInstance -ClassName %s -ErrorAction Stop).%s", className, property)
	if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command).Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

func collectDeviceIdentity(hardwareID string) map[string]interface{} {
	identity := map[string]interface{}{
		"hardware_id":   hardwareID,
		"serial_number": queryCIMValue("Win32_BIOS", "SerialNumber"),
		"manufacturer":  queryCIMValue("Win32_ComputerSystem", "Manufacturer"),
		"model":         queryCIMValue("Win32_ComputerSystem", "Model"),
	}

	if key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
		defer key.Close()
		if domain, _, err := key.GetStringValue("Domain"); err == nil && strings.TrimSpace(domain) != "" {
			identity["domain"] = strings.TrimSpace(domain)
		} else if domain, _, err := key.GetStringValue("NV Domain"); err == nil {
			identity["domain"] = strings.TrimSpace(domain)
		}
	}

	if out, err := exec.Command("dsregcmd.exe", "/status").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch key {
			case "DeviceId":
				identity["entra_device_id"] = value
			case "TenantId":
				identity["entra_tenant_id"] = value
			case "AzureAdJoined":
				identity["entra_joined"] = strings.EqualFold(value, "YES")
			case "DomainJoined":
				identity["domain_joined"] = strings.EqualFold(value, "YES")
			case "DomainName":
				if _, exists := identity["domain"]; !exists {
					identity["domain"] = value
				}
			}
		}
	}
	return identity
}

func collectOSInfo() map[string]interface{} {
	info := map[string]interface{}{
		"os_name":    runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpu_model":  "Unknown",
		"os_edition": "Unknown",
	}

	// CPU model from registry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err == nil {
		if v, _, err := k.GetStringValue("ProcessorNameString"); err == nil {
			info["cpu_model"] = strings.TrimSpace(v)
		}
		k.Close()
	}

	// OS edition from registry
	k2, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err == nil {
		if v, _, err := k2.GetStringValue("EditionID"); err == nil {
			info["os_edition"] = v
		}
		if v, _, err := k2.GetStringValue("CurrentBuildNumber"); err == nil {
			info["os_build"] = v
		}
		if v, _, err := k2.GetStringValue("DisplayVersion"); err == nil {
			info["os_version"] = v
		}
		k2.Close()
	}

	return info
}

// ── helpers ──────────────────────────────────────────────────────────────────

func strVal(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func round1(f float64) float64 { return float64(int(f*10)) / 10 }
func round2(f float64) float64 { return float64(int(f*100)) / 100 }
func round3(f float64) float64 { return float64(int(f*1000)) / 1000 }
func max64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
