package main

// policy.go — Local Group Policy template application.
//
// Applies pre-built, code-reviewed Local Group
// Policy (.pol) templates via Microsoft's LGPO.exe, the officially
// supported CLI for importing/exporting local GPO settings without Active
// Directory: https://www.microsoft.com/en-us/download/details.aspx?id=55319
//
// Security model: PUSH_LOCAL_POLICY job payloads select a `template` key
// into policyTemplates below — never a raw file path, registry key, or
// LGPO argument. This keeps PUSH_LOCAL_POLICY from becoming a second,
// less-audited RUN_CMD: every template that can ever run is defined here
// in reviewed source, and its .pol asset is fixed at build/deploy time,
// not taken from the network. Keep the key set in sync with
// server/policy_templates.py and this file's policy template catalog.
//
// Bundling: LGPO.exe and each template's .pol file ship in a `policy`
// folder next to the installed warden-agent.exe (installDir\policy) —
// placed there by whatever packages the installer, the same prerequisite
// documented for the Python build's policy/ bundling directory.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

type policyTemplate struct {
	description string
	polAsset    string
	lgpoFlag    string
}

var policyTemplates = map[string]policyTemplate{
	"restrict-standard-user-tools": {
		description: "Disable Task Manager and regedit for standard (non-admin) users",
		polAsset:    "restrict-standard-user-tools.pol",
		// Non-Administrators user policy, NOT machine-wide — this
		// template's whole point is that admins stay unaffected.
		// Verified live: applying this same .pol via /m instead writes
		// to HKLM and disables Task Manager/regedit for every account
		// including admins.
		lgpoFlag: "/un",
	},
	"applocker-pin-warden-publisher": {
		description: "AppLocker: only allow warden-agent.exe if signed by our publisher cert",
		polAsset:    "applocker-warden-publisher.pol",
		lgpoFlag:    "/m", // AppLocker rules are Computer-scoped policy
	},
	"firewall-scope-agent-egress": {
		description: "Windows Firewall: scope the agent process to reach only the Warden server",
		polAsset:    "firewall-scope-agent.pol",
		lgpoFlag:    "/m", // Windows Firewall rules are Computer-scoped policy
	},
}

func policyAssetsDir() string {
	return filepath.Join(installDir, "policy")
}

// applyPolicyTemplate applies a named, pre-built Local Group Policy
// template via LGPO.exe. template must be a key of policyTemplates — never
// a path or argument taken directly from a job payload.
func applyPolicyTemplate(template string) (int, string, error) {
	spec, ok := policyTemplates[template]
	if !ok {
		return 1, "", fmt.Errorf("unknown policy template: %s", template)
	}

	lgpoExe := filepath.Join(policyAssetsDir(), "LGPO.exe")
	polPath := filepath.Join(policyAssetsDir(), spec.polAsset)

	cmd := exec.Command(lgpoExe, "/q", spec.lgpoFlag, polPath)
	type commandResult struct {
		out []byte
		err error
	}
	done := make(chan commandResult, 1)
	go func() {
		out, err := boundedCombinedOutput(cmd)
		done <- commandResult{out: out, err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			code := 1
			if exitErr, ok := result.err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			}
			return code, string(result.out), result.err
		}
		return 0, string(result.out), nil
	case <-time.After(60 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return 1, "", fmt.Errorf("LGPO.exe timed out after 60s")
	}
}

func pushLocalPolicy(p map[string]interface{}) (int, string, error) {
	// New-style payload: {"settings": {"key": value, ...}} — individually
	// addressable, parameterized settings (see policySettingsCatalog below).
	// Falls through to the legacy fixed-template payload for backward
	// compatibility with the three pre-built LGPO templates above.
	if settings, ok := p["settings"].(map[string]interface{}); ok {
		return applyPolicySettings(settings)
	}
	template, _ := p["template"].(string)
	return applyPolicyTemplate(template)
}

// ── Individually addressable policy settings ──────────────────────────────
//
// Unlike the fixed LGPO templates above, these are single, parameterized
// registry-backed settings — the same "Administrative Templates" mechanism
// Group Policy itself uses under HKLM\SOFTWARE\Policies\..., which applies
// locally without any Active Directory domain controller. A job payload
// selects a setting *key* from policySettingsCatalog below plus a value —
// never a raw registry path — and the value is validated here against the
// setting's declared kind/range/enum before anything is written. Keep this
// catalog in sync with server/policy_settings.py (the server's independent
// copy, used to validate before a job is ever dispatched — defense in
// depth, same principle as the legacy template catalog).
type policySettingKind string

const (
	kindBool   policySettingKind = "bool"
	kindInt    policySettingKind = "int"
	kindEnum   policySettingKind = "enum"
	kindString policySettingKind = "string"
)

type policySettingMeta struct {
	kind       policySettingKind
	min, max   int      // kindInt only
	enumValues []string // kindEnum only
}

var policySettingsCatalog = map[string]policySettingMeta{
	// Remote Desktop
	"rdp_enabled":                     {kind: kindBool},
	"rdp_network_level_auth_required": {kind: kindBool},

	// USB & Storage
	"usb_storage_enabled":             {kind: kindBool},
	"autorun_enabled":                 {kind: kindBool},
	"removable_storage_write_protect": {kind: kindBool},

	// Screen Lock
	"screen_lock_timeout_minutes":   {kind: kindInt, min: 1, max: 120},
	"require_ctrl_alt_del":          {kind: kindBool},
	"hide_last_signed_in_user":      {kind: kindBool},
	"lock_screen_camera_enabled":    {kind: kindBool},
	"lock_screen_slideshow_enabled": {kind: kindBool},

	// Windows Update
	"windows_update_auto_download":                     {kind: kindBool},
	"windows_update_auto_restart_with_users_logged_in": {kind: kindBool},
	"windows_update_defer_feature_updates_days":        {kind: kindInt, min: 0, max: 365},

	// Security
	"smartscreen_enabled":                         {kind: kindBool},
	"defender_realtime_protection_enabled":        {kind: kindBool},
	"defender_cloud_delivered_protection_enabled": {kind: kindBool},
	"defender_scan_removable_drives_enabled":      {kind: kindBool},
	"firewall_all_profiles_enabled":               {kind: kindBool},
	"windows_firewall_rules":                      {kind: kindString},
	"guest_account_enabled":                       {kind: kindBool},
	"powershell_script_block_logging_enabled":     {kind: kindBool},
	"windows_script_host_enabled":                 {kind: kindBool},
	"remote_registry_service_enabled":             {kind: kindBool},
	"remote_assistance_enabled":                   {kind: kindBool},
	"powershell_execution_policy": {
		kind:       kindEnum,
		enumValues: []string{"Restricted", "AllSigned", "RemoteSigned", "Unrestricted"},
	},
	"telemetry_level": {
		kind:       kindEnum,
		enumValues: []string{"Security", "Basic", "Enhanced", "Full"},
	},

	// Privacy
	"cortana_enabled":           {kind: kindBool},
	"onedrive_sync_enabled":     {kind: kindBool},
	"windows_spotlight_enabled": {kind: kindBool},
	"windows_store_enabled":     {kind: kindBool},
	"llmnr_enabled":             {kind: kindBool},
}

// ── ADMX-derived catalog (policy_catalog.json) ─────────────────────────────
//
// The settings above are hand-picked, individually reviewed, with
// special-cased logic where the naive registry write isn't the whole story
// (RDP's Home-edition gate, USB storage scoped to exclude usbhub, Guest
// account via net.exe, Defender's Tamper Protection caveat). Everything
// below can load a larger, systematically generated catalog sourced by the
// deployment operator from locally licensed ADMX/ADML policy definitions
// (scripts/extract-admx-catalog.ps1 + filter_admx_catalog.py), covering a
// curated set of categories relevant to a general Windows fleet (Windows
// Update, Defender, Firewall, Remote Desktop/TerminalServer, Explorer,
// Start Menu, Power, Search, Printing, etc — see filter_admx_catalog.py's
// ALLOWED_CATEGORIES for the full list). Upstream intentionally ships an
// empty catalog; see docs/POLICY_CATALOG.md. A locally reviewed catalog is embedded via
// go:embed, so — same security invariant as the hand-picked catalog above —
// the agent only ever writes to a registry key/value that shipped in its
// own reviewed build, never one supplied at runtime by the server/network.
type admxOption struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type admxEntry struct {
	Key         string       `json:"key"`
	Label       string       `json:"label"`
	Category    string       `json:"category"`
	Kind        string       `json:"kind"` // bool | int | enum | string
	RegistryKey string       `json:"registryKey"`
	Scope       string       `json:"scope"`
	ValueName   string       `json:"valueName"`
	RegType     string       `json:"regType"` // dword | string
	Min         int          `json:"min"`
	Max         int          `json:"max"`
	Options     []admxOption `json:"options"`
	SupportedOn string       `json:"supportedOn"`
	Help        string       `json:"help"`
	Readonly    bool         `json:"readonly"` // status-only (e.g. BitLocker) -- never pushable, see filter_admx_catalog.py's READONLY_CATEGORIES
}

//go:embed policy_catalog.json
var admxCatalogJSON []byte

var admxCatalog map[string]admxEntry

func init() {
	var entries []admxEntry
	if err := json.Unmarshal(admxCatalogJSON, &entries); err != nil {
		return // leave admxCatalog nil — generic lookups just find nothing
	}
	admxCatalog = make(map[string]admxEntry, len(entries))
	for _, e := range entries {
		admxCatalog[e.Key] = e
	}
}

func validateAdmxValue(entry admxEntry, value interface{}) error {
	if entry.Scope != "machine" {
		return fmt.Errorf("%s: unsupported policy scope %q", entry.Key, entry.Scope)
	}
	if entry.Readonly {
		return fmt.Errorf("%s: this setting is status-only and cannot be pushed (see category %s)", entry.Key, entry.Category)
	}
	switch entry.Kind {
	case "bool":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: expected a boolean value", entry.Key)
		}
	case "int":
		f, ok := value.(float64)
		if !ok {
			return fmt.Errorf("%s: expected a numeric value", entry.Key)
		}
		n := int(f)
		if n < entry.Min || n > entry.Max {
			return fmt.Errorf("%s: value %d out of range [%d, %d]", entry.Key, n, entry.Min, entry.Max)
		}
	case "enum":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: expected a string value", entry.Key)
		}
		for _, opt := range entry.Options {
			if opt.Label == s {
				return nil
			}
		}
		return fmt.Errorf("%s: %q is not one of the allowed options", entry.Key, s)
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s: expected a string value", entry.Key)
		}
	}
	return nil
}

func applyAdmxSetting(entry admxEntry, value interface{}) error {
	switch entry.Kind {
	case "bool":
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(entry.RegistryKey, entry.ValueName, v)

	case "int":
		return writePolicyDword(entry.RegistryKey, entry.ValueName, uint32(int(value.(float64))))

	case "enum":
		label := value.(string)
		var stored string
		found := false
		for _, opt := range entry.Options {
			if opt.Label == label {
				stored = opt.Value
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: option %q not found", entry.Key, label)
		}
		if entry.RegType == "string" {
			return writePolicyString(entry.RegistryKey, entry.ValueName, stored)
		}
		n, err := strconv.ParseUint(stored, 10, 32)
		if err != nil {
			return fmt.Errorf("%s: invalid stored enum value %q: %w", entry.Key, stored, err)
		}
		return writePolicyDword(entry.RegistryKey, entry.ValueName, uint32(n))

	case "string":
		return writePolicyString(entry.RegistryKey, entry.ValueName, value.(string))

	default:
		return fmt.Errorf("%s: unsupported kind %q", entry.Key, entry.Kind)
	}
}

func readAdmxSetting(entry admxEntry) (interface{}, error) {
	switch entry.Kind {
	case "bool":
		v, ok, err := readPolicyDword(entry.RegistryKey, entry.ValueName)
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "int":
		v, ok, err := readPolicyDword(entry.RegistryKey, entry.ValueName)
		if err != nil || !ok {
			return nil, err
		}
		return float64(v), nil

	case "enum":
		if entry.RegType == "string" {
			v, ok, err := readPolicyString(entry.RegistryKey, entry.ValueName)
			if err != nil || !ok {
				return nil, err
			}
			for _, opt := range entry.Options {
				if opt.Value == v {
					return opt.Label, nil
				}
			}
			return nil, nil
		}
		v, ok, err := readPolicyDword(entry.RegistryKey, entry.ValueName)
		if err != nil || !ok {
			return nil, err
		}
		for _, opt := range entry.Options {
			n, convErr := strconv.ParseUint(opt.Value, 10, 32)
			if convErr == nil && uint32(n) == v {
				return opt.Label, nil
			}
		}
		return nil, nil

	case "string":
		v, ok, err := readPolicyString(entry.RegistryKey, entry.ValueName)
		if err != nil || !ok {
			return nil, err
		}
		return v, nil

	default:
		return nil, fmt.Errorf("%s: unsupported kind %q", entry.Key, entry.Kind)
	}
}

func validatePolicySettingValue(key string, value interface{}) error {
	meta, ok := policySettingsCatalog[key]
	if !ok {
		if entry, admxOk := admxCatalog[key]; admxOk {
			return validateAdmxValue(entry, value)
		}
		return fmt.Errorf("unknown policy setting: %s", key)
	}
	switch meta.kind {
	case kindBool:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: expected a boolean value", key)
		}
	case kindInt:
		f, ok := value.(float64) // JSON numbers decode as float64
		if !ok {
			return fmt.Errorf("%s: expected a numeric value", key)
		}
		n := int(f)
		if n < meta.min || n > meta.max {
			return fmt.Errorf("%s: value %d out of range [%d, %d]", key, n, meta.min, meta.max)
		}
	case kindEnum:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: expected a string value", key)
		}
		for _, v := range meta.enumValues {
			if v == s {
				return nil
			}
		}
		return fmt.Errorf("%s: %q is not one of %v", key, s, meta.enumValues)
	case kindString:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: expected a string value", key)
		}
		if key == "windows_firewall_rules" {
			_, err := parseManagedFirewallRules(s)
			return err
		}
	}
	return nil
}

func writePolicyDword(path, name string, v uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, v)
}

func writePolicyString(path, name, v string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, v)
}

func deletePolicyValue(path, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func clearPolicySetting(key string) error {
	if key == "windows_firewall_rules" {
		if err := removeManagedFirewallRules(); err != nil {
			return err
		}
		return deletePolicyValue(`SOFTWARE\Warden\ManagedPolicy`, "WindowsFirewallRules")
	}
	if entry, ok := admxCatalog[key]; ok {
		return deletePolicyValue(entry.RegistryKey, entry.ValueName)
	}
	type valueRef struct{ path, name string }
	refs := map[string][]valueRef{
		"rdp_network_level_auth_required":                  {{`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication"}},
		"screen_lock_timeout_minutes":                      {{`SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveActive"}, {`SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaverIsSecure"}, {`SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveTimeOut"}},
		"windows_update_auto_download":                     {{`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate"}},
		"smartscreen_enabled":                              {{`SOFTWARE\Policies\Microsoft\Windows\System`, "EnableSmartScreen"}},
		"powershell_execution_policy":                      {{`SOFTWARE\Policies\Microsoft\Windows\PowerShell`, "EnableScripts"}, {`SOFTWARE\Policies\Microsoft\Windows\PowerShell`, "ExecutionPolicy"}},
		"autorun_enabled":                                  {{`SOFTWARE\Policies\Microsoft\Windows\Explorer`, "NoDriveTypeAutoRun"}},
		"require_ctrl_alt_del":                             {{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableCAD"}},
		"defender_realtime_protection_enabled":             {{`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring"}},
		"removable_storage_write_protect":                  {{`SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`, "Deny_Write"}},
		"hide_last_signed_in_user":                         {{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "dontdisplaylastusername"}},
		"lock_screen_camera_enabled":                       {{`SOFTWARE\Policies\Microsoft\Windows\Personalization`, "NoLockScreenCamera"}},
		"lock_screen_slideshow_enabled":                    {{`SOFTWARE\Policies\Microsoft\Windows\Personalization`, "NoLockScreenSlideshow"}},
		"windows_update_auto_restart_with_users_logged_in": {{`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoRebootWithLoggedOnUsers"}},
		"windows_update_defer_feature_updates_days":        {{`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DeferFeatureUpdates"}, {`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DeferFeatureUpdatesPeriodInDays"}},
		"defender_cloud_delivered_protection_enabled":      {{`SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`, "SpynetReporting"}},
		"defender_scan_removable_drives_enabled":           {{`SOFTWARE\Policies\Microsoft\Windows Defender\Scan`, "DisableRemovableDriveScanning"}},
		"powershell_script_block_logging_enabled":          {{`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging"}},
		"windows_script_host_enabled":                      {{`SOFTWARE\Policies\Microsoft\Windows Script Host\Settings`, "Enabled"}},
		"remote_assistance_enabled":                        {{`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, "fAllowToGetHelp"}},
		"telemetry_level":                                  {{`SOFTWARE\Policies\Microsoft\Windows\DataCollection`, "AllowTelemetry"}},
		"cortana_enabled":                                  {{`SOFTWARE\Policies\Microsoft\Windows\Windows Search`, "AllowCortana"}},
		"onedrive_sync_enabled":                            {{`SOFTWARE\Policies\Microsoft\Windows\OneDrive`, "DisableFileSyncNGSC"}},
		"windows_spotlight_enabled":                        {{`SOFTWARE\Policies\Microsoft\Windows\CloudContent`, "DisableWindowsSpotlightFeatures"}},
		"windows_store_enabled":                            {{`SOFTWARE\Policies\Microsoft\WindowsStore`, "RemoveWindowsStore"}},
		"llmnr_enabled":                                    {{`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast"}},
	}
	if key == "firewall_all_profiles_enabled" {
		for _, profile := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
			if err := deletePolicyValue(`SOFTWARE\Policies\Microsoft\WindowsFirewall\`+profile, "EnableFirewall"); err != nil {
				return err
			}
		}
		return nil
	}
	for _, ref := range refs[key] {
		if err := deletePolicyValue(ref.path, ref.name); err != nil {
			return err
		}
	}
	return nil
}

// applyPolicySetting validates then applies a single catalog setting.
// value must already be a decoded JSON value (bool, float64, or string).
func applyPolicySetting(key string, value interface{}) error {
	if err := validatePolicySettingValue(key, value); err != nil {
		return err
	}
	switch key {
	case "windows_firewall_rules":
		return applyManagedFirewallRules(value.(string))
	case "rdp_enabled":
		if value.(bool) {
			if home, edition := isHomeEdition(); home {
				return fmt.Errorf("Remote Desktop hosting is not available on Windows Home (edition: %s) — writing this registry value would have no effect", edition)
			}
		}
		deny := uint32(1)
		if value.(bool) {
			deny = 0
		}
		return writePolicyDword(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections", deny)

	case "rdp_network_level_auth_required":
		if value.(bool) {
			if home, edition := isHomeEdition(); home {
				return fmt.Errorf("Remote Desktop hosting is not available on Windows Home (edition: %s) — writing this registry value would have no effect", edition)
			}
		}
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication", v)

	case "usb_storage_enabled":
		// USBSTOR only — the USB Mass Storage driver class. Keyboards, mice,
		// and other non-storage USB peripherals use the separate HID driver
		// class and are never affected by this setting.
		start := uint32(4)
		if value.(bool) {
			start = 3
		}
		return writePolicyDword(`SYSTEM\CurrentControlSet\Services\USBSTOR`, "Start", start)

	case "screen_lock_timeout_minutes":
		minutes := int(value.(float64))
		path := `SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`
		if err := writePolicyString(path, "ScreenSaveActive", "1"); err != nil {
			return err
		}
		if err := writePolicyString(path, "ScreenSaverIsSecure", "1"); err != nil {
			return err
		}
		return writePolicyString(path, "ScreenSaveTimeOut", strconv.Itoa(minutes*60))

	case "windows_update_auto_download":
		noAuto := uint32(1)
		if value.(bool) {
			noAuto = 0
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate", noAuto)

	case "smartscreen_enabled":
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\System`, "EnableSmartScreen", v)

	case "powershell_execution_policy":
		path := `SOFTWARE\Policies\Microsoft\Windows\PowerShell`
		if err := writePolicyDword(path, "EnableScripts", 1); err != nil {
			return err
		}
		return writePolicyString(path, "ExecutionPolicy", value.(string))

	case "autorun_enabled":
		v := uint32(0x91) // default: prompt on removable media
		if !value.(bool) {
			v = 0xFF // disable AutoPlay/AutoRun on all drive types
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Explorer`, "NoDriveTypeAutoRun", v)

	case "require_ctrl_alt_del":
		v := uint32(1) // DisableCAD=1 means CAD is NOT required
		if value.(bool) {
			v = 0
		}
		return writePolicyDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableCAD", v)

	case "firewall_all_profiles_enabled":
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		base := `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
		for _, profile := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
			if err := writePolicyDword(base+profile, "EnableFirewall", v); err != nil {
				return fmt.Errorf("%s: %w", profile, err)
			}
		}
		return nil

	case "guest_account_enabled":
		// Not registry-backed like the others — the built-in Guest account's
		// enabled/disabled state lives in the SAM database, not a policy key.
		// "net user" is the standard, official mechanism (same as doing it by
		// hand from an elevated prompt).
		state := "no"
		if value.(bool) {
			state = "yes"
		}
		out, err := exec.Command("net", "user", "Guest", "/active:"+state).CombinedOutput()
		if err != nil {
			return fmt.Errorf("net user Guest /active:%s: %w (%s)", state, err, string(out))
		}
		return nil

	case "defender_realtime_protection_enabled":
		// Silently no-ops on a machine with Tamper Protection turned on for
		// Windows Defender (by design on Microsoft's side — Tamper Protection
		// exists specifically to block exactly this kind of registry-based
		// change from anything other than the Windows Security app itself).
		disable := uint32(0)
		if !value.(bool) {
			disable = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`,
			"DisableRealtimeMonitoring", disable)

	case "removable_storage_write_protect":
		// Removable Disks device class GUID — the same subkey Group Policy's
		// "All Removable Storage classes: Deny all access" setting targets.
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(
			`SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`,
			"Deny_Write", v)

	case "hide_last_signed_in_user":
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "dontdisplaylastusername", v)

	case "lock_screen_camera_enabled":
		v := uint32(0)
		if !value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Personalization`, "NoLockScreenCamera", v)

	case "lock_screen_slideshow_enabled":
		v := uint32(0)
		if !value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Personalization`, "NoLockScreenSlideshow", v)

	case "windows_update_auto_restart_with_users_logged_in":
		v := uint32(1) // 1 = block auto-restart while users are logged in (safer default)
		if value.(bool) {
			v = 0
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoRebootWithLoggedOnUsers", v)

	case "windows_update_defer_feature_updates_days":
		days := int(value.(float64))
		path := `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
		if err := writePolicyDword(path, "DeferFeatureUpdates", 1); err != nil {
			return err
		}
		return writePolicyDword(path, "DeferFeatureUpdatesPeriodInDays", uint32(days))

	case "defender_cloud_delivered_protection_enabled":
		v := uint32(0)
		if value.(bool) {
			v = 2 // 2 = advanced (Microsoft's recommended "on" value); 0 = off
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`, "SpynetReporting", v)

	case "defender_scan_removable_drives_enabled":
		v := uint32(0)
		if !value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows Defender\Scan`, "DisableRemovableDriveScanning", v)

	case "powershell_script_block_logging_enabled":
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging", v)

	case "windows_script_host_enabled":
		v := uint32(1)
		if !value.(bool) {
			v = 0
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows Script Host\Settings`, "Enabled", v)

	case "remote_registry_service_enabled":
		start := uint32(4) // disabled
		if value.(bool) {
			start = 3 // manual/on-demand — matches Windows' own default
		}
		return writePolicyDword(`SYSTEM\CurrentControlSet\Services\RemoteRegistry`, "Start", start)

	case "remote_assistance_enabled":
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, "fAllowToGetHelp", v)

	case "telemetry_level":
		levels := map[string]uint32{"Security": 0, "Basic": 1, "Enhanced": 2, "Full": 3}
		v, ok := levels[value.(string)]
		if !ok {
			return fmt.Errorf("telemetry_level: unrecognized value %q", value)
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\DataCollection`, "AllowTelemetry", v)

	case "cortana_enabled":
		v := uint32(0)
		if value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Windows Search`, "AllowCortana", v)

	case "onedrive_sync_enabled":
		v := uint32(0)
		if !value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\OneDrive`, "DisableFileSyncNGSC", v)

	case "windows_spotlight_enabled":
		v := uint32(0)
		if !value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows\CloudContent`, "DisableWindowsSpotlightFeatures", v)

	case "windows_store_enabled":
		v := uint32(0)
		if !value.(bool) {
			v = 1
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\WindowsStore`, "RemoveWindowsStore", v)

	case "llmnr_enabled":
		v := uint32(1)
		if !value.(bool) {
			v = 0
		}
		return writePolicyDword(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast", v)

	default:
		if entry, ok := admxCatalog[key]; ok {
			return applyAdmxSetting(entry, value)
		}
		return fmt.Errorf("unknown policy setting: %s", key)
	}
}

// isHomeEdition reports whether this machine is running a Home-tier Windows
// edition (no Remote Desktop host support, among other Pro/Enterprise-only
// features). Windows' internal EditionID for Home is "Core"/"CoreN"/
// "CoreSingleLanguage"/"CoreCountrySpecific" — NOT the string "Home", which
// only appears in the user-facing product name. (A pre-existing check
// elsewhere in this codebase, collectSysinfo's rdp_capable field, checked
// for "Home" in EditionID and was therefore always wrong — fixed alongside
// this to reuse the same, correct check.)
func isHomeEdition() (bool, string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return false, "unknown"
	}
	defer k.Close()
	edition, _, err := k.GetStringValue("EditionID")
	if err != nil {
		return false, "unknown"
	}
	return strings.HasPrefix(edition, "Core"), edition
}

// applyPolicySettings validates the whole bundle before touching Windows,
// snapshots live semantic values, and rolls attempted settings back in
// reverse order on failure. This prevents an invalid later key from leaving
// an earlier setting applied and substantially narrows runtime partial state.
type managedFirewallRule struct {
	Name            string   `json:"name"`
	Enabled         *bool    `json:"enabled,omitempty"`
	Direction       string   `json:"direction"`
	Action          string   `json:"action"`
	Priority        int      `json:"priority,omitempty"`
	Protocol        string   `json:"protocol"`
	Program         string   `json:"program"`
	LocalPorts      []string `json:"local_ports"`
	RemotePorts     []string `json:"remote_ports"`
	RemoteAddresses []string `json:"remote_addresses"`
	Profiles        []string `json:"profiles"`
}

var firewallRuleName = regexp.MustCompile(`^[^\r\n"]{1,120}$`)
var firewallPort = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?$`)

func parseManagedFirewallRules(raw string) ([]managedFirewallRule, error) {
	var rules []managedFirewallRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, fmt.Errorf("windows_firewall_rules: invalid JSON: %w", err)
	}
	if len(rules) > 100 {
		return nil, fmt.Errorf("windows_firewall_rules: expected at most 100 rules")
	}
	for i := range rules {
		r := &rules[i]
		r.Name = strings.TrimSpace(r.Name)
		r.Direction = strings.ToLower(strings.TrimSpace(r.Direction))
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
		if r.Protocol == "" {
			r.Protocol = "any"
		}
		if !firewallRuleName.MatchString(r.Name) || (r.Direction != "in" && r.Direction != "out") ||
			(r.Action != "allow" && r.Action != "block") ||
			(r.Protocol != "any" && r.Protocol != "tcp" && r.Protocol != "udp") {
			return nil, fmt.Errorf("windows_firewall_rules[%d]: invalid name, direction, action, or protocol", i+1)
		}
		if r.Priority < -1000 || r.Priority > 1000 {
			return nil, fmt.Errorf("windows_firewall_rules[%d]: priority must be between -1000 and 1000", i+1)
		}
		if r.Program != "" {
			clean := filepath.Clean(r.Program)
			if !filepath.IsAbs(clean) || strings.Contains(clean, `..\`) {
				return nil, fmt.Errorf("windows_firewall_rules[%d]: program must be an absolute path", i+1)
			}
			r.Program = clean
		}
		if r.Direction == "out" && r.Action == "block" {
			if r.Program == "" {
				return nil, fmt.Errorf("windows_firewall_rules[%d]: outbound block rules must target an application to preserve the Warden control connection", i+1)
			}
			if strings.EqualFold(filepath.Base(r.Program), "warden-agent.exe") {
				return nil, fmt.Errorf("windows_firewall_rules[%d]: the Warden agent cannot be blocked", i+1)
			}
		}
		for _, ports := range [][]string{r.LocalPorts, r.RemotePorts} {
			if len(ports) > 50 {
				return nil, fmt.Errorf("windows_firewall_rules[%d]: too many ports", i+1)
			}
			for _, p := range ports {
				m := firewallPort.FindStringSubmatch(p)
				if m == nil {
					return nil, fmt.Errorf("windows_firewall_rules[%d]: invalid port %q", i+1, p)
				}
				lo, _ := strconv.Atoi(m[1])
				hi := lo
				if m[2] != "" {
					hi, _ = strconv.Atoi(m[2])
				}
				if lo < 1 || hi > 65535 || lo > hi {
					return nil, fmt.Errorf("windows_firewall_rules[%d]: invalid port %q", i+1, p)
				}
			}
		}
		if len(r.RemoteAddresses) > 100 {
			return nil, fmt.Errorf("windows_firewall_rules[%d]: too many addresses", i+1)
		}
		for _, address := range r.RemoteAddresses {
			if _, err := netip.ParsePrefix(address); err != nil {
				if _, ipErr := netip.ParseAddr(address); ipErr != nil {
					return nil, fmt.Errorf("windows_firewall_rules[%d]: invalid IP/CIDR %q", i+1, address)
				}
			}
		}
		for _, profile := range r.Profiles {
			switch strings.ToLower(profile) {
			case "domain", "private", "public":
			default:
				return nil, fmt.Errorf("windows_firewall_rules[%d]: invalid profile", i+1)
			}
		}
	}
	return rules, nil
}

func applyManagedFirewallRules(raw string) error {
	rules, err := parseManagedFirewallRules(raw)
	if err != nil {
		return err
	}
	if err := removeManagedFirewallRules(); err != nil {
		return err
	}
	if err := ensureControlPlaneFirewallRule(); err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		args := []string{"advfirewall", "firewall", "add", "rule", "name=Warden Managed: " + rule.Name,
			"dir=" + rule.Direction, "action=" + rule.Action, "enable=yes"}
		if rule.Protocol != "any" {
			args = append(args, "protocol="+strings.ToUpper(rule.Protocol))
		}
		if rule.Program != "" {
			args = append(args, "program="+rule.Program)
		}
		if len(rule.LocalPorts) > 0 {
			args = append(args, "localport="+strings.Join(rule.LocalPorts, ","))
		}
		if len(rule.RemotePorts) > 0 {
			args = append(args, "remoteport="+strings.Join(rule.RemotePorts, ","))
		}
		if len(rule.RemoteAddresses) > 0 {
			args = append(args, "remoteip="+strings.Join(rule.RemoteAddresses, ","))
		}
		if len(rule.Profiles) > 0 {
			args = append(args, "profile="+strings.Join(rule.Profiles, ","))
		}
		if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
			_ = removeManagedFirewallRules()
			return fmt.Errorf("create firewall rule %q: %w (%s)", rule.Name, err, strings.TrimSpace(string(out)))
		}
	}
	return writePolicyString(`SOFTWARE\Warden\ManagedPolicy`, "WindowsFirewallRules", raw)
}

func removeManagedFirewallRules() error {
	// `netsh advfirewall firewall add rule` has no group/grouping argument on
	// supported Windows builds. Rules are therefore owned by an unambiguous
	// display-name prefix and removed through the supported firewall cmdlets.
	const script = `Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Warden Managed: *' } | Remove-NetFirewallRule -ErrorAction Stop`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove existing Warden firewall rules: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Keep the signed/pinned agent's HTTPS channel explicitly allowed. Windows
// gives block rules precedence over allow rules, so the policy validators also
// forbid Warden-created broad outbound blocks and rules targeting this binary.
// Rules owned by another administrator are never silently deleted here.
func ensureControlPlaneFirewallRule() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve Warden executable for firewall rule: %w", err)
	}
	parsed, err := url.Parse(serverURL())
	if err != nil {
		return fmt.Errorf("parse Warden server URL for firewall rule: %w", err)
	}
	port := parsed.Port()
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid Warden server port for firewall rule")
	}
	name := "Warden Control Plane: Agent HTTPS"
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	args := []string{
		"advfirewall", "firewall", "add", "rule", "name=" + name,
		"dir=out", "action=allow", "enable=yes",
		"program=" + executable, "protocol=TCP", "remoteport=" + port, "profile=any",
	}
	if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("create Warden control-plane firewall rule: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	p2pName := "Warden Direct P2P: Agent UDP"
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+p2pName).Run()
	p2pArgs := []string{
		"advfirewall", "firewall", "add", "rule", "name=" + p2pName,
		"dir=in", "action=allow", "enable=yes", "edge=yes",
		"program=" + executable, "protocol=UDP",
		fmt.Sprintf("localport=%d", agentP2PUDPMin), "profile=any",
	}
	if out, err := exec.Command("netsh", p2pArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("create Warden direct P2P firewall rule: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyPolicySettings(settings map[string]interface{}) (int, string, error) {
	keys := make([]string, 0, len(settings))
	for key, value := range settings {
		if err := validatePolicySettingValue(key, value); err != nil {
			return 1, "No settings applied", err
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	previous := make(map[string]interface{}, len(keys))
	for _, key := range keys {
		value, err := readPolicySetting(key)
		if err != nil {
			return 1, "No settings applied", fmt.Errorf("snapshot %s: %w", key, err)
		}
		previous[key] = value
	}

	var attempted []string
	for _, key := range keys {
		value := settings[key]
		attempted = append(attempted, key)
		if err := applyPolicySetting(key, value); err != nil {
			var rollbackErrors []string
			for i := len(attempted) - 1; i >= 0; i-- {
				rollbackKey := attempted[i]
				old := previous[rollbackKey]
				var rollbackErr error
				if old == nil {
					rollbackErr = clearPolicySetting(rollbackKey)
				} else {
					rollbackErr = applyPolicySetting(rollbackKey, old)
				}
				if rollbackErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Sprintf("%s: %v", rollbackKey, rollbackErr))
				}
			}
			msg := "Policy bundle rolled back"
			if len(rollbackErrors) > 0 {
				msg += "; rollback errors: " + strings.Join(rollbackErrors, "; ")
			}
			return 1, msg, fmt.Errorf("%s: %w", key, err)
		}
	}
	return 0, fmt.Sprintf("Applied: %s", strings.Join(keys, ", ")), nil
}

// ── Drift detection ────────────────────────────────────────────────────────

func readPolicyDword(path, name string) (uint32, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if err == registry.ErrNotExist {
			return 0, false, nil
		}
		return 0, false, err
	}
	return uint32(v), true, nil
}

func readPolicyString(path, name string) (string, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return "", false, nil
		}
		return "", false, err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		if err == registry.ErrNotExist {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// readPolicySetting reads the current live value of a single catalog
// setting, decoded back to the same shape (bool/int-minutes/enum string)
// applyPolicySetting would have written. Returns (nil, nil) when the
// setting isn't currently configured by policy at all (never pushed, or
// cleared by something else) — that's a valid, common state, not an error.
func readPolicySetting(key string) (interface{}, error) {
	switch key {
	case "windows_firewall_rules":
		v, ok, err := readPolicyString(`SOFTWARE\Warden\ManagedPolicy`, "WindowsFirewallRules")
		if err != nil || !ok {
			return nil, err
		}
		return v, nil
	case "rdp_enabled":
		v, ok, err := readPolicyDword(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "usb_storage_enabled":
		v, ok, err := readPolicyDword(`SYSTEM\CurrentControlSet\Services\USBSTOR`, "Start")
		if err != nil || !ok {
			return nil, err
		}
		return v == 3, nil

	case "screen_lock_timeout_minutes":
		v, ok, err := readPolicyString(`SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveTimeOut")
		if err != nil || !ok {
			return nil, err
		}
		seconds, convErr := strconv.Atoi(v)
		if convErr != nil {
			return nil, nil
		}
		return float64(seconds / 60), nil

	case "windows_update_auto_download":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "smartscreen_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\System`, "EnableSmartScreen")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "powershell_execution_policy":
		v, ok, err := readPolicyString(`SOFTWARE\Policies\Microsoft\Windows\PowerShell`, "ExecutionPolicy")
		if err != nil || !ok {
			return nil, err
		}
		return v, nil

	case "autorun_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Explorer`, "NoDriveTypeAutoRun")
		if err != nil || !ok {
			return nil, err
		}
		return v != 0xFF, nil

	case "require_ctrl_alt_del":
		v, ok, err := readPolicyDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableCAD")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "firewall_all_profiles_enabled":
		base := `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
		allEnabled := true
		anyConfigured := false
		for _, profile := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
			v, ok, err := readPolicyDword(base+profile, "EnableFirewall")
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			anyConfigured = true
			if v != 1 {
				allEnabled = false
			}
		}
		if !anyConfigured {
			return nil, nil
		}
		return allEnabled, nil

	case "guest_account_enabled":
		out, err := exec.Command("net", "user", "Guest").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("net user Guest: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Account active") {
				return strings.Contains(strings.ToLower(line), "yes"), nil
			}
		}
		return nil, nil

	case "defender_realtime_protection_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "rdp_network_level_auth_required":
		v, ok, err := readPolicyDword(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "removable_storage_write_protect":
		v, ok, err := readPolicyDword(
			`SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`, "Deny_Write")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "hide_last_signed_in_user":
		v, ok, err := readPolicyDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "dontdisplaylastusername")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "lock_screen_camera_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Personalization`, "NoLockScreenCamera")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "lock_screen_slideshow_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Personalization`, "NoLockScreenSlideshow")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "windows_update_auto_restart_with_users_logged_in":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoRebootWithLoggedOnUsers")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "windows_update_defer_feature_updates_days":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "DeferFeatureUpdatesPeriodInDays")
		if err != nil || !ok {
			return nil, err
		}
		return float64(v), nil

	case "defender_cloud_delivered_protection_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`, "SpynetReporting")
		if err != nil || !ok {
			return nil, err
		}
		return v != 0, nil

	case "defender_scan_removable_drives_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows Defender\Scan`, "DisableRemovableDriveScanning")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "powershell_script_block_logging_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "windows_script_host_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows Script Host\Settings`, "Enabled")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "remote_registry_service_enabled":
		v, ok, err := readPolicyDword(`SYSTEM\CurrentControlSet\Services\RemoteRegistry`, "Start")
		if err != nil || !ok {
			return nil, err
		}
		return v != 4, nil

	case "remote_assistance_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, "fAllowToGetHelp")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "telemetry_level":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\DataCollection`, "AllowTelemetry")
		if err != nil || !ok {
			return nil, err
		}
		names := map[uint32]string{0: "Security", 1: "Basic", 2: "Enhanced", 3: "Full"}
		if name, ok := names[v]; ok {
			return name, nil
		}
		return nil, nil

	case "cortana_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\Windows Search`, "AllowCortana")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	case "onedrive_sync_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\OneDrive`, "DisableFileSyncNGSC")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "windows_spotlight_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\CloudContent`, "DisableWindowsSpotlightFeatures")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "windows_store_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\WindowsStore`, "RemoveWindowsStore")
		if err != nil || !ok {
			return nil, err
		}
		return v == 0, nil

	case "llmnr_enabled":
		v, ok, err := readPolicyDword(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast")
		if err != nil || !ok {
			return nil, err
		}
		return v == 1, nil

	default:
		if entry, ok := admxCatalog[key]; ok {
			return readAdmxSetting(entry)
		}
		return nil, fmt.Errorf("unknown policy setting: %s", key)
	}
}

// checkPolicyDrift reads the current live value of every catalog setting
// (or, if keys is non-empty, just that subset — e.g. one saved template's
// settings, so checking "did this specific template drift" doesn't have to
// scan all ~1300 registry values every time) and returns it as a JSON
// object in the job's log output, {key: value|null} — null means "not
// currently configured by policy" (never pushed, or cleared by something
// else since). The server compares this against policy_state's
// last-known-applied values to judge match/drift; the agent itself has no
// notion of what was last pushed, so it just reports what's actually there
// now.
func checkPolicyDrift(keys []string) (int, string, error) {
	readOne := func(key string) (interface{}, error) {
		if _, ok := policySettingsCatalog[key]; ok {
			return readPolicySetting(key)
		}
		if entry, ok := admxCatalog[key]; ok {
			return readAdmxSetting(entry)
		}
		return nil, fmt.Errorf("unknown policy setting: %s", key)
	}

	if len(keys) > 0 {
		result := make(map[string]interface{}, len(keys))
		for _, key := range keys {
			v, err := readOne(key)
			if err != nil {
				logWarn("Policy drift check: %s: %v", key, err)
				continue
			}
			result[key] = v
		}
		out, err := json.Marshal(result)
		if err != nil {
			return 1, "", fmt.Errorf("encode drift result: %w", err)
		}
		return 0, string(out), nil
	}

	result := make(map[string]interface{}, len(policySettingsCatalog)+len(admxCatalog))
	for key := range policySettingsCatalog {
		v, err := readPolicySetting(key)
		if err != nil {
			logWarn("Policy drift check: %s: %v", key, err)
			continue
		}
		result[key] = v
	}
	for key := range admxCatalog {
		v, err := readAdmxSetting(admxCatalog[key])
		if err != nil {
			logWarn("Policy drift check: %s: %v", key, err)
			continue
		}
		result[key] = v
	}
	out, err := json.Marshal(result)
	if err != nil {
		return 1, "", fmt.Errorf("encode drift result: %w", err)
	}
	return 0, string(out), nil
}

// collectConfiguredPolicyValues returns the current effective value for every
// Warden-known machine policy. A nil value is intentional and means the
// policy is not configured on this machine. Reporting the full catalog makes
// first-install inventory authoritative and also lets the server distinguish
// "not configured" from "the agent never checked this setting".
func collectConfiguredPolicyValues() map[string]interface{} {
	result := make(map[string]interface{}, len(policySettingsCatalog)+len(admxCatalog))
	for key := range policySettingsCatalog {
		value, err := readPolicySetting(key)
		if err != nil {
			logWarn("Initial policy inventory: %s: %v", key, err)
			continue
		}
		result[key] = value
	}
	for key, entry := range admxCatalog {
		value, err := readAdmxSetting(entry)
		if err != nil {
			logWarn("Initial policy inventory: %s: %v", key, err)
			continue
		}
		result[key] = value
	}
	return result
}
