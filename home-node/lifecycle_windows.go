//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const homeServiceName = "WardenHomeNode"
const homeP2PFirewallName = "Warden Home: Direct P2P UDP"

func windowsPaths() (string, string) {
	programFiles := os.Getenv("ProgramFiles")
	programData := os.Getenv("ProgramData")
	return filepath.Join(programFiles, "WardenHome", "warden-home-node.exe"), filepath.Join(programData, "WardenHome", "warden-home.json")
}

type homeService struct{ configPath string }

func (service *homeService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runConfiguredServer(service.configPath, stop) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case request := <-requests:
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

func runAsSystemService() (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, err
	}
	executable, _ := windowsPaths()
	if err := ensureHomeP2PFirewallRule(executable); err != nil {
		return true, err
	}
	_, configPath := windowsPaths()
	return true, svc.Run(homeServiceName, &homeService{configPath: configPath})
}

func installSystemService(sourceConfig string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService(homeServiceName); err == nil {
		existing.Close()
		return errors.New("Warden Home service is already installed")
	}
	executable, configPath := windowsPaths()
	if err := copyInstallFiles(sourceConfig, executable, configPath); err != nil {
		return err
	}
	if err := ensureHomeP2PFirewallRule(executable); err != nil {
		return err
	}
	service, err := manager.CreateService(homeServiceName, executable, mgr.Config{DisplayName: "Warden Home Node", StartType: mgr.StartAutomatic}, "serve", "-config", configPath)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Start()
}

func uninstallSystemService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(homeServiceName)
	if err != nil {
		return err
	}
	_, _ = service.Control(svc.Stop)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, queryErr := service.Query()
		if queryErr == nil && status.State == svc.Stopped {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if status, queryErr := service.Query(); queryErr == nil && status.State != svc.Stopped {
		service.Close()
		return errors.New("Warden Home service did not stop; program files were preserved")
	}
	err = service.Delete()
	service.Close()
	removeHomeP2PFirewallRule()
	executable, _ := windowsPaths()
	_ = windows.MoveFileEx(windows.StringToUTF16Ptr(executable), nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	return err
}

func upgradeSystemService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(homeServiceName)
	if err != nil {
		return errors.New("Warden Home service is not installed")
	}
	defer service.Close()
	_, _ = service.Control(svc.Stop)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, queryErr := service.Query()
		if queryErr == nil && status.State == svc.Stopped {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if status, queryErr := service.Query(); queryErr != nil || status.State != svc.Stopped {
		return errors.New("Warden Home service did not stop; installed binary was preserved")
	}
	executable, _ := windowsPaths()
	if err := copyCurrentExecutable(executable); err != nil {
		return err
	}
	if err := ensureHomeP2PFirewallRule(executable); err != nil {
		return err
	}
	return service.Start()
}

func managedUpdateDirectory() string {
	return filepath.Join(os.Getenv("ProgramData"), "WardenHome", "update")
}

func scheduleManagedUpdate(manifest string) error {
	staged := filepath.Join(filepath.Dir(manifest), "warden-home-node.new")
	command := exec.Command(staged, "apply-update", "-config", configPathInUse, "-manifest", manifest)
	return command.Start()
}

func installManagedUpdate(staged string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(homeServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	_, _ = service.Control(svc.Stop)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, queryErr := service.Query()
		if queryErr == nil && status.State == svc.Stopped {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if status, queryErr := service.Query(); queryErr != nil || status.State != svc.Stopped {
		return errors.New("Warden Home service did not stop; managed update was not installed")
	}
	executable, _ := windowsPaths()
	backup := filepath.Join(filepath.Dir(staged), "warden-home-node.backup.exe")
	replacement := executable + ".new"
	if err = copyFileExact(executable, backup, 0700); err != nil {
		return err
	}
	if err = copyFileExact(staged, replacement, 0700); err != nil {
		return err
	}
	if err = os.Remove(executable); err != nil {
		return err
	}
	if err = os.Rename(replacement, executable); err != nil {
		_ = copyFileExact(backup, executable, 0700)
		return err
	}
	if err = ensureHomeP2PFirewallRule(executable); err == nil {
		err = service.Start()
	}
	if err == nil {
		deadline = time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			status, queryErr := service.Query()
			if queryErr == nil && status.State == svc.Running {
				_ = os.Remove(backup)
				_ = windows.MoveFileEx(windows.StringToUTF16Ptr(staged), nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
				return nil
			}
			time.Sleep(time.Second)
		}
		err = errors.New("updated Warden Home service did not become healthy")
	}
	_ = os.Remove(executable)
	if rollbackErr := copyFileExact(backup, executable, 0700); rollbackErr != nil {
		return fmt.Errorf("%v; rollback failed: %w", err, rollbackErr)
	}
	_ = service.Start()
	return fmt.Errorf("%v; previous Warden Home binary restored", err)
}

func ensureHomeP2PFirewallRule(executable string) error {
	removeHomeP2PFirewallRule()
	args := []string{
		"advfirewall", "firewall", "add", "rule", "name=" + homeP2PFirewallName,
		"dir=in", "action=allow", "enable=yes", "edge=yes",
		"program=" + executable, "protocol=UDP",
		fmt.Sprintf("localport=%d", homeP2PUDPMin), "profile=any",
	}
	if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("create Warden Home direct P2P firewall rule: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeHomeP2PFirewallRule() {
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+homeP2PFirewallName).Run()
}
