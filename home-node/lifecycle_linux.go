//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const systemdUnit = "/etc/systemd/system/warden-home-node.service"
const systemdUpdateUnit = "/etc/systemd/system/warden-home-node-update.service"
const systemdUpdatePathUnit = "/etc/systemd/system/warden-home-node-update.path"
const linuxManagedUpdateDir = "/var/lib/warden-home-update"

func runAsSystemService() (bool, error) { return false, nil }

func ensureHomeServiceUser() error {
	if exec.Command("id", "-u", "warden-home").Run() == nil {
		return nil
	}
	return exec.Command(
		"useradd", "--system", "--user-group", "--home-dir", "/var/lib/warden-home",
		"--create-home", "--shell", "/usr/sbin/nologin", "warden-home",
	).Run()
}

func copyPrivateAsset(source, destination string, mode os.FileMode) error {
	if source == "" {
		return nil
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destination, raw, mode); err != nil {
		return err
	}
	return os.Chmod(destination, mode)
}

func secureInstalledLinuxConfig(path string) (config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var installed config
	if err := json.Unmarshal(raw, &installed); err != nil {
		return config{}, err
	}
	root := filepath.Clean(installed.Root)
	if !filepath.IsAbs(root) || root == string(os.PathSeparator) || strings.ContainsAny(root, "\r\n") {
		return config{}, fmt.Errorf("storage root must be a safe absolute directory")
	}
	protectedRoots := []string{"/etc", "/usr", "/bin", "/sbin", "/boot", "/proc", "/sys", "/dev", "/run", "/var", "/home", "/mnt", "/srv", "/opt"}
	for _, protected := range protectedRoots {
		if root == protected {
			return config{}, fmt.Errorf("storage root %s is too broad", root)
		}
	}
	assetDir := "/etc/warden-home/tls"
	if err := os.MkdirAll(assetDir, 0700); err != nil {
		return config{}, err
	}
	assets := []struct {
		source *string
		name   string
		mode   os.FileMode
	}{
		{&installed.TLSCert, "server-cert.pem", 0644},
		{&installed.TLSKey, "server-key.pem", 0600},
		{&installed.ClientCA, "client-ca.pem", 0644},
		{&installed.ClientCert, "client-cert.pem", 0644},
		{&installed.ClientKey, "client-key.pem", 0600},
	}
	for _, asset := range assets {
		if *asset.source == "" {
			continue
		}
		destination := filepath.Join(assetDir, asset.name)
		if err := copyPrivateAsset(*asset.source, destination, asset.mode); err != nil {
			return config{}, fmt.Errorf("copy %s: %w", asset.name, err)
		}
		*asset.source = destination
	}
	encoded, err := json.MarshalIndent(installed, "", "  ")
	if err != nil {
		return config{}, err
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
		return config{}, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return config{}, err
	}
	if err := exec.Command("chown", "-R", "warden-home:warden-home", "/etc/warden-home", root).Run(); err != nil {
		return config{}, err
	}
	return installed, nil
}

func installSystemService(sourceConfig string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install must run as root")
	}
	if _, err := os.Stat(systemdUnit); err == nil {
		return fmt.Errorf("Warden Home service is already installed")
	}
	if err := ensureHomeServiceUser(); err != nil {
		return fmt.Errorf("create warden-home service account: %w", err)
	}
	if err := copyInstallFiles(sourceConfig, "/usr/local/bin/warden-home-node", "/etc/warden-home/warden-home.json"); err != nil {
		return err
	}
	installed, err := secureInstalledLinuxConfig("/etc/warden-home/warden-home.json")
	if err != nil {
		return err
	}
	unit := fmt.Sprintf("[Unit]\nDescription=Warden Home Node\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=warden-home\nGroup=warden-home\nUMask=0077\nExecStart=/usr/local/bin/warden-home-node serve -config /etc/warden-home/warden-home.json\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nProtectClock=true\nRestrictSUIDSGID=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nReadWritePaths=/etc/warden-home /var/lib/warden-home-update %q\n\n[Install]\nWantedBy=multi-user.target\n", installed.Root)
	if err := os.WriteFile(systemdUnit, []byte(unit), 0644); err != nil {
		return err
	}
	if err := ensureManagedUpdateUnits(); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "enable", "--now", "warden-home-node.service").Run()
}

func uninstallSystemService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must run as root")
	}
	if err := exec.Command("systemctl", "disable", "--now", "warden-home-node.service").Run(); err != nil {
		return err
	}
	_ = os.Remove(systemdUnit)
	_ = exec.Command("systemctl", "disable", "--now", "warden-home-node-update.path").Run()
	_ = os.Remove(systemdUpdateUnit)
	_ = os.Remove(systemdUpdatePathUnit)
	_ = os.Remove("/usr/local/bin/warden-home-node")
	return exec.Command("systemctl", "daemon-reload").Run()
}

func upgradeSystemService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("upgrade must run as root")
	}
	if _, err := os.Stat(systemdUnit); err != nil {
		return fmt.Errorf("Warden Home service is not installed")
	}
	if err := exec.Command("systemctl", "stop", "warden-home-node.service").Run(); err != nil {
		return err
	}
	if err := copyCurrentExecutable("/usr/local/bin/warden-home-node"); err != nil {
		_ = exec.Command("systemctl", "start", "warden-home-node.service").Run()
		return err
	}
	if err := os.Chmod("/usr/local/bin/warden-home-node", 0755); err != nil {
		return err
	}
	if err := ensureManagedUpdateUnits(); err != nil {
		return err
	}
	return exec.Command("systemctl", "start", "warden-home-node.service").Run()
}

func managedUpdateDirectory() string { return linuxManagedUpdateDir }

func ensureManagedUpdateUnits() error {
	if err := os.MkdirAll(linuxManagedUpdateDir, 0700); err != nil {
		return err
	}
	if err := exec.Command("chown", "warden-home:warden-home", linuxManagedUpdateDir).Run(); err != nil {
		return err
	}
	if raw, err := os.ReadFile(systemdUnit); err == nil {
		unit := string(raw)
		if !strings.Contains(unit, "ReadWritePaths=/etc/warden-home "+linuxManagedUpdateDir+" ") {
			unit = strings.Replace(
				unit,
				"ReadWritePaths=/etc/warden-home ",
				"ReadWritePaths=/etc/warden-home "+linuxManagedUpdateDir+" ",
				1,
			)
			if err := os.WriteFile(systemdUnit, []byte(unit), 0644); err != nil {
				return err
			}
		}
	}
	service := "[Unit]\nDescription=Apply signed Warden Home update\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/warden-home-node apply-update -config /etc/warden-home/warden-home.json -manifest /var/lib/warden-home-update/update.json\n"
	path := "[Unit]\nDescription=Watch for signed Warden Home updates\n\n[Path]\nPathExists=/var/lib/warden-home-update/ready\nUnit=warden-home-node-update.service\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(systemdUpdateUnit, []byte(service), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(systemdUpdatePathUnit, []byte(path), 0644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "enable", "--now", "warden-home-node-update.path").Run()
}

func scheduleManagedUpdate(manifest string) error {
	return os.WriteFile(filepath.Join(filepath.Dir(manifest), "ready"), []byte("ready\n"), 0600)
}

func installManagedUpdate(staged string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("managed update helper must run as root")
	}
	const executable = "/usr/local/bin/warden-home-node"
	backup := filepath.Join(filepath.Dir(staged), "warden-home-node.backup")
	replacement := executable + ".new"
	if err := exec.Command("systemctl", "stop", "warden-home-node.service").Run(); err != nil {
		return err
	}
	if err := copyFileExact(executable, backup, 0755); err != nil {
		_ = exec.Command("systemctl", "start", "warden-home-node.service").Run()
		return err
	}
	if err := copyFileExact(staged, replacement, 0755); err != nil {
		_ = exec.Command("systemctl", "start", "warden-home-node.service").Run()
		return err
	}
	if err := os.Rename(replacement, executable); err != nil {
		_ = exec.Command("systemctl", "start", "warden-home-node.service").Run()
		return err
	}
	if err := exec.Command("systemctl", "start", "warden-home-node.service").Run(); err == nil {
		for attempt := 0; attempt < 30; attempt++ {
			if exec.Command("systemctl", "is-active", "--quiet", "warden-home-node.service").Run() == nil {
				_ = os.Remove(backup)
				return nil
			}
			time.Sleep(time.Second)
		}
	}
	_ = copyFileExact(backup, executable, 0755)
	_ = exec.Command("systemctl", "start", "warden-home-node.service").Run()
	return fmt.Errorf("updated service failed health check; previous binary restored")
}
