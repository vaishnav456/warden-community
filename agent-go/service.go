package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// installedExePath is where the service is always registered to run from,
// regardless of where "install" was originally launched from (a staging
// directory under an MSI's Program Files component, an extracted zip in
// Downloads, etc.) — matching the zip installer's install.bat, which has
// always copied warden-agent.exe here before registering the service (see
// _INSTALL_BAT in build-service/builder.py). installService() used to use
// os.Executable() directly instead, which meant the service pointed at
// whatever transient location it happened to be launched from; on the MSI
// path that was C:\Program Files\WardenAgentInstaller, so the registered
// service silently broke once Windows Installer's own file-cost bookkeeping
// left that directory alone (or if malfunctioned differently, it would
// simply reuse a staging exe with no adjacent config.json ever copied into
// dataDir, since nothing else did that on the MSI path either).
var installedExePath = filepath.Join(dataDir, "warden-agent.exe")

// selfRelocateAndSeedConfig replicates install.bat's two copy steps in Go
// so every install path (MSI, zip+bat, or a future one) gets them for free
// instead of each packaging format needing to reimplement file copying
// itself. Copies the currently-running exe to installedExePath (unless
// already running from there), and seeds dataDir's config.json from an
// adjacent one next to the running exe -- but only if dataDir doesn't
// already have a config.json, so a repair/reinstall never clobbers a real,
// already-enrolled config with a fresh bootstrap one.
func selfRelocateAndSeedConfig() error {
	ensureDirs()

	curExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current executable path: %w", err)
	}
	curExeAbs, _ := filepath.Abs(curExe)
	targetAbs, _ := filepath.Abs(installedExePath)
	if !strings.EqualFold(curExeAbs, targetAbs) {
		if err := copyFile(curExe, installedExePath); err != nil {
			return fmt.Errorf("copy exe to %s: %w", installedExePath, err)
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		adjacentConfig := filepath.Join(filepath.Dir(curExe), "config.json")
		if _, err := os.Stat(adjacentConfig); err == nil {
			if err := copyFile(adjacentConfig, configPath); err != nil {
				return fmt.Errorf("copy config.json to %s: %w", configPath, err)
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func serviceInstalled() (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open service: %w", err)
	}
	s.Close()
	return true, nil
}

// reconnectConfig builds the one-time bootstrap configuration used when a
// retired endpoint's agent is still installed. The server matches the stable
// installation ID to the inactive historical row; everything else comes from
// the newly generated, tenant-scoped installer.
func reconnectConfig(current, bootstrap AgentConfig) (AgentConfig, error) {
	if strings.TrimSpace(bootstrap.EnrollmentToken) == "" {
		return AgentConfig{}, fmt.Errorf("installer has no enrollment token")
	}
	if strings.TrimSpace(bootstrap.ServerURL) == "" ||
		strings.TrimSpace(bootstrap.ServerEd25519Pubkey) == "" ||
		len(effectiveCertFingerprints(bootstrap)) == 0 {
		return AgentConfig{}, fmt.Errorf("installer bootstrap configuration is incomplete")
	}
	installationID := strings.TrimSpace(current.InstallationID)
	if installationID == "" {
		var err error
		installationID, err = newInstallationID()
		if err != nil {
			return AgentConfig{}, fmt.Errorf("create installation identity: %w", err)
		}
	}
	bootstrap.InstallationID = installationID
	bootstrap.EndpointID = ""
	return bootstrap, nil
}

func stopServiceAndWait(max time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	if status.State != svc.Stopped && status.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop protected service (run the MSI as administrator): %w", err)
		}
	}
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query stopping service: %w", err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("service did not stop within %s", max)
}

// reconnectExistingService updates and re-enrols the existing service in
// place. MSI invokes this command as LocalSystem, which is required because
// the service and data directory deliberately deny service-control/write
// access to ordinary administrators after tamper protection is applied.
func reconnectExistingService() error {
	curExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get installer executable: %w", err)
	}
	bootstrapBytes, err := os.ReadFile(filepath.Join(filepath.Dir(curExe), "config.json"))
	if err != nil {
		return fmt.Errorf("read installer config.json: %w", err)
	}
	var bootstrap AgentConfig
	if err := json.Unmarshal(bootstrapBytes, &bootstrap); err != nil {
		return fmt.Errorf("parse installer config.json: %w", err)
	}
	var current AgentConfig
	if data, readErr := os.ReadFile(configPath); readErr == nil {
		if err := json.Unmarshal(data, &current); err != nil {
			return fmt.Errorf("parse installed config.json: %w", err)
		}
	}
	next, err := reconnectConfig(current, bootstrap)
	if err != nil {
		return err
	}

	if err := stopServiceAndWait(20 * time.Second); err != nil {
		return err
	}
	if err := copyFile(curExe, installedExePath); err != nil {
		return fmt.Errorf("update installed agent binary: %w", err)
	}
	configBytes, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode reconnect config: %w", err)
	}
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		return fmt.Errorf("write reconnect config: %w", err)
	}
	for _, path := range []string{
		credentialsPath, pendingEnrollPath, clientKeyPath, clientCertPath,
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear old enrollment credential %s: %w", path, err)
		}
	}
	if err := startService(); err != nil {
		return fmt.Errorf("restart service: %w", err)
	}
	return nil
}

const (
	serviceName = "WardenAgent"
)

func serviceDisplayName() string {
	if buildServiceDisplayNameB64 != "" {
		if raw, err := base64.RawURLEncoding.DecodeString(buildServiceDisplayNameB64); err == nil {
			name := strings.TrimSpace(string(raw))
			if name != "" && len(name) <= 128 && utf8.ValidString(name) {
				return name
			}
		}
	}
	return "Warden Endpoint Agent"
}

type wardenService struct{}

func (s *wardenService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		runAgent(stopCh)
	}()

	const accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange
	status <- svc.Status{
		State:   svc.Running,
		Accepts: accepts,
	}

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stopCh)
				select {
				case <-doneCh:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			case svc.SessionChange:
				// Feeds desiredRemoteDesktop()'s lock/unlock tracking in
				// elevation.go — see the comment there for why this replaced
				// polling WTSInfoEx's SessionFlags.
				recordSessionChange(req.EventType)
				status <- svc.Status{State: svc.Running, Accepts: accepts}
			default:
				status <- svc.Status{State: svc.Running, Accepts: accepts}
			}
		case <-doneCh:
			return false, 0
		}
	}
}

func installService() error {
	// Always registers installedExePath, not wherever this process happens
	// to be currently running from -- see selfRelocateAndSeedConfig(),
	// which main.go's "install" case calls first to make sure a real copy
	// actually exists there before this registers it as the service binary.
	exePath := installedExePath
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName(),
		Description: serviceDisplayName() + ". Do not stop unless instructed by IT.",
		StartType:   mgr.StartAutomatic,
		ServiceType: 0x10, // SERVICE_WIN32_OWN_PROCESS
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Without this, Windows' default "Take No Action" on service failure
	// means an unhandled panic, an OOM kill, or any other abnormal
	// termination leaves the endpoint silently dark until someone notices
	// and manually restarts it. Escalating delays avoid a tight crash loop
	// if something is persistently broken (e.g. a corrupt config file).
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := s.SetRecoveryActions(recoveryActions, uint32((24 * time.Hour).Seconds())); err != nil {
		logWarn("Could not configure service recovery actions: %v", err)
	}
	// Also restart on a clean-looking exit with a nonzero code (e.g. a
	// fatal startup error), not just an unclean crash — the endpoint
	// coming back and retrying is always preferable to staying down.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		logWarn("Could not enable recovery actions on non-crash failures: %v", err)
	}
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	return s.Start()
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}
