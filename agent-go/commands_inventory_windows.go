package main

import (
	"encoding/json"
	"fmt"
	diskPkg "github.com/shirou/gopsutil/v3/disk"
	memPkg "github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ── Sysinfo / software inventory ──────────────────────────────────────────────

func collectSysinfo() (int, string, error) {
	info := map[string]interface{}{
		"os_name":  runtime.GOOS,
		"arch":     runtime.GOARCH,
		"hostname": func() string { h, _ := os.Hostname(); return h }(),
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("ProcessorNameString"); err == nil {
			info["cpu_model"] = strings.TrimSpace(v)
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("EditionID"); err == nil {
			info["os_edition"] = v
			// EditionID for Home is "Core"/"CoreN"/"CoreSingleLanguage" etc —
			// never literally "Home" (that's only the user-facing product
			// name) — checking for "Home" here always evaluated true.
			info["rdp_capable"] = !strings.HasPrefix(v, "Core")
		}
		k.Close()
	}
	if vm, err := memPkg.VirtualMemory(); err == nil {
		info["ram_total_gb"] = round2(float64(vm.Total) / (1024 * 1024 * 1024))
	}
	if du, err := diskPkg.Usage(`C:\`); err == nil {
		info["disk_total_gb"] = round2(float64(du.Total) / (1024 * 1024 * 1024))
		info["disk_free_gb"] = round2(float64(du.Free) / (1024 * 1024 * 1024))
	}
	// A dedicated /api/agent/sysinfo route (sysinfo() in routes/agent_api.py
	// -> db.update_endpoint_sysinfo) exists for exactly this data -- same
	// gap as COLLECT_USERS/COLLECT_SOFTWARE had (see collectUsers() above):
	// nothing ever actually called it. It's only ever populated once, at
	// enrollment (collectOSInfo() in agent.go, via /enroll's os_info field),
	// so the "Collect System Info" button and the scheduled COLLECT_SYSINFO
	// job both silently never refresh anything after that first snapshot,
	// despite reporting a full JSON payload as job success.
	if _, err := apiPostAuth("/api/agent/sysinfo", info); err != nil {
		return 1, "", fmt.Errorf("report sysinfo: %w", err)
	}
	b, _ := json.Marshal(info)
	return 0, string(b), nil
}

func collectSoftware() (int, string, error) {
	type swEntry struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		Publisher       string `json:"publisher"`
		InstallDate     string `json:"install_date"`
		InstallLocation string `json:"install_location,omitempty"`
		ExecutablePath  string `json:"executable_path,omitempty"`
	}
	seen := make(map[string]bool)
	var software []swEntry
	regPaths := []struct {
		hive registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	for _, rp := range regPaths {
		k, err := registry.OpenKey(rp.hive, rp.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subkeys, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sub := range subkeys {
			sk, err := registry.OpenKey(rp.hive, rp.path+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			pub, _, _ := sk.GetStringValue("Publisher")
			instDate, _, _ := sk.GetStringValue("InstallDate")
			installLocation, _, _ := sk.GetStringValue("InstallLocation")
			displayIcon, _, _ := sk.GetStringValue("DisplayIcon")
			sk.Close()
			if name == "" {
				continue
			}
			key := strings.ToLower(name) + "|" + strings.ToLower(ver)
			if seen[key] {
				continue
			}
			seen[key] = true
			software = append(software, swEntry{
				Name: name, Version: ver, Publisher: pub, InstallDate: instDate,
				InstallLocation: normaliseInventoryPath(installLocation),
				ExecutablePath:  displayIconExecutable(displayIcon),
			})
		}
	}
	// A dedicated /api/agent/software route (report_software() in
	// routes/agent_api.py) has existed for the software_inventory table --
	// same gap as COLLECT_USERS had (see collectUsers() above): nothing
	// ever actually called it. Returning the JSON as the job's own log
	// output (the previous behavior) made it visible in the Jobs tab, but
	// never wrote a single row to software_inventory, so the Software tab
	// stayed empty regardless of how many times this ran successfully.
	if _, err := apiPostAuth("/api/agent/software", map[string]interface{}{"software": software}); err != nil {
		return 1, "", fmt.Errorf("report software: %w", err)
	}
	return 0, fmt.Sprintf("Reported %d software items", len(software)), nil
}

// DisplayIcon is the closest standard Windows uninstall-registry field to the
// actual application binary.  It commonly contains either a quoted executable
// followed by an icon index ("C:\\App\\app.exe",0) or a plain executable.
// Do not guess from UninstallString: that would create a firewall rule for the
// uninstaller rather than for the application the administrator selected.
func displayIconExecutable(value string) string {
	value = strings.TrimSpace(os.ExpandEnv(value))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, `"`) {
		if end := strings.Index(value[1:], `"`); end >= 0 {
			value = value[1 : end+1]
		}
	} else if comma := strings.LastIndex(value, ","); comma >= 0 {
		value = value[:comma]
	}
	value = normaliseInventoryPath(value)
	if !strings.EqualFold(filepath.Ext(value), ".exe") || !filepath.IsAbs(value) {
		return ""
	}
	return value
}

func normaliseInventoryPath(value string) string {
	value = strings.Trim(strings.TrimSpace(os.ExpandEnv(value)), `"`)
	if value == "" || !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Clean(value)
}
