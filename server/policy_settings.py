"""
policy_settings.py — Catalog of individually addressable PUSH_LOCAL_POLICY
settings, as opposed to policy_templates.py's fixed, pre-built LGPO
templates. Each setting maps to specific, reviewed registry key(s) in
agent-go/policy.go's policySettingsCatalog — the server never accepts an
arbitrary registry path or value type from a request, only a setting *key*
from this catalog plus a value validated against its declared kind/range/
enum here, before an escalation/job is ever created. The agent independently
re-validates the same way (defense in depth — a compromised or buggy server
still can't smuggle an unvalidated value past the agent).

Keep this catalog's keys and kinds in sync with agent-go/policy.go's
policySettingsCatalog.

Two tiers, both merged into POLICY_SETTINGS below:
  - HAND_PICKED_SETTINGS: individually reviewed, with special-cased agent
    logic where a naive registry write isn't the whole story (RDP's Home-
    edition gate, USB storage scoped to exclude the hub driver, Guest
    account via net.exe, Defender's Tamper Protection caveat).
  - An optional operator-generated ADMX catalog (policy_catalog.json) —
    generated from locally licensed ADMX/ADML policy definitions via
    scripts/extract-admx-catalog.ps1 + filter_admx_catalog.py, covering a
    curated set of categories relevant to a general Windows fleet. See
    that script for the category allowlist and why most of the raw
    ADMX set (Internet Explorer, App-V, UE-V, BitLocker enforcement,
    server/domain-only policies, etc.) isn't included.
"""
import json
import ipaddress
import ntpath
import pathlib


def _validate_firewall_rules_json(value):
    if not isinstance(value, str):
        raise ValueError("windows_firewall_rules: expected a JSON string")
    try:
        rules = json.loads(value)
    except ValueError as exc:
        raise ValueError("windows_firewall_rules: invalid JSON") from exc
    if not isinstance(rules, list) or len(rules) > 100:
        raise ValueError("windows_firewall_rules: expected a list of at most 100 rules")
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            raise ValueError(f"windows_firewall_rules[{index}]: expected an object")
        name = str(rule.get("name") or "").strip()
        if not name or len(name) > 120 or any(c in name for c in '\r\n"'):
            raise ValueError(f"windows_firewall_rules[{index}]: invalid name")
        if "enabled" in rule and not isinstance(rule["enabled"], bool):
            raise ValueError(f"windows_firewall_rules[{index}]: enabled must be true or false")
        if rule.get("direction") not in ("in", "out"):
            raise ValueError(f"windows_firewall_rules[{index}]: direction must be in or out")
        if rule.get("action") not in ("allow", "block"):
            raise ValueError(f"windows_firewall_rules[{index}]: action must be allow or block")
        priority = rule.get("priority", 0)
        if not isinstance(priority, int) or isinstance(priority, bool) or not -1000 <= priority <= 1000:
            raise ValueError(f"windows_firewall_rules[{index}]: priority must be between -1000 and 1000")
        protocol = rule.get("protocol", "any")
        if not isinstance(protocol, str) or protocol.lower() not in ("any", "tcp", "udp"):
            raise ValueError(f"windows_firewall_rules[{index}]: invalid protocol")
        program = str(rule.get("program") or "").strip()
        if program and (not ntpath.isabs(program) or ".." in program.replace("/", "\\").split("\\")):
            raise ValueError(f"windows_firewall_rules[{index}]: program must be an absolute Windows path")
        if rule.get("direction") == "out" and rule.get("action") == "block":
            if not program:
                raise ValueError(
                    f"windows_firewall_rules[{index}]: outbound block rules must target an application "
                    "so the Warden control connection cannot be blocked"
                )
            if ntpath.basename(program).casefold() == "warden-agent.exe":
                raise ValueError(f"windows_firewall_rules[{index}]: the Warden agent cannot be blocked")
        for field in ("local_ports", "remote_ports"):
            ports = rule.get(field, [])
            if not isinstance(ports, list) or len(ports) > 50:
                raise ValueError(f"windows_firewall_rules[{index}]: {field} must be a list")
            for port in ports:
                text = str(port)
                bounds = text.split("-", 1)
                if any(not part.isdigit() for part in bounds):
                    raise ValueError(f"windows_firewall_rules[{index}]: invalid {field}")
                numbers = [int(part) for part in bounds]
                if any(number < 1 or number > 65535 for number in numbers) or len(numbers) == 2 and numbers[0] > numbers[1]:
                    raise ValueError(f"windows_firewall_rules[{index}]: invalid {field}")
        addresses = rule.get("remote_addresses", [])
        if not isinstance(addresses, list) or len(addresses) > 100:
            raise ValueError(f"windows_firewall_rules[{index}]: remote_addresses must be a list")
        for address in addresses:
            try:
                ipaddress.ip_network(str(address), strict=False)
            except ValueError as exc:
                raise ValueError(f"windows_firewall_rules[{index}]: invalid IP/CIDR {address}") from exc
        profiles = rule.get("profiles", [])
        if not isinstance(profiles, list) or any(
                not isinstance(profile, str) or profile.lower() not in {"domain", "private", "public"}
                for profile in profiles):
            raise ValueError(f"windows_firewall_rules[{index}]: invalid profiles")
    return rules

HAND_PICKED_SETTINGS = {
    "rdp_enabled": {
        "category": "Remote Desktop",
        "label": "Allow Remote Desktop connections",
        "kind": "bool",
    },
    "usb_storage_enabled": {
        "category": "USB & Storage",
        "label": "Allow USB storage devices (flash drives, external disks)",
        "kind": "bool",
        # Scoped to the USB Mass Storage driver class (USBSTOR) only — never
        # touches the USB hub driver, so keyboards, mice, and other non-
        # storage USB peripherals are never affected by this setting.
        "help": "Keyboards, mice, and other non-storage USB devices are never affected.",
    },
    "screen_lock_timeout_minutes": {
        "category": "Screen Lock",
        "label": "Idle minutes before the screen locks (all users)",
        "kind": "int",
        "min": 1,
        "max": 120,
    },
    "windows_update_auto_download": {
        "category": "Windows Update",
        "label": "Automatically download Windows updates",
        "kind": "bool",
    },
    "smartscreen_enabled": {
        "category": "Security",
        "label": "Windows Defender SmartScreen (apps & files)",
        "kind": "bool",
    },
    "powershell_execution_policy": {
        "category": "Security",
        "label": "PowerShell script execution policy",
        "kind": "enum",
        "options": ["Restricted", "AllSigned", "RemoteSigned", "Unrestricted"],
    },
    "autorun_enabled": {
        "category": "USB & Storage",
        "label": "Allow AutoPlay/AutoRun prompts for removable media",
        "kind": "bool",
    },
    "require_ctrl_alt_del": {
        "category": "Security",
        "label": "Require Ctrl+Alt+Del before sign-in",
        "kind": "bool",
    },
    "firewall_all_profiles_enabled": {
        "category": "Security",
        "label": "Windows Firewall (domain, private & public profiles)",
        "kind": "bool",
    },
    "windows_firewall_rules": {
        "category": "Windows Firewall",
        "label": "Application and IP firewall rules",
        "kind": "string",
        "multiline": True,
        "help": "JSON rule list managed in an isolated Warden Firewall group. Supports program path, IP/CIDR, ports, direction, protocol, and allow/block.",
        "placeholder": '[{"name":"Allow ERP","direction":"out","action":"allow","protocol":"tcp","program":"C:\\\\Program Files\\\\ERP\\\\erp.exe","remote_addresses":["10.20.0.0/16"],"remote_ports":["443"]}]',
    },
    "guest_account_enabled": {
        "category": "Security",
        "label": "Built-in Guest account",
        "kind": "bool",
        "help": "Not registry-backed — applied via the standard 'net user Guest' mechanism.",
    },
    "defender_realtime_protection_enabled": {
        "category": "Security",
        "label": "Windows Defender real-time protection",
        "kind": "bool",
        "help": "Has no effect on a machine with Defender Tamper Protection turned on.",
    },
    "rdp_network_level_auth_required": {
        "category": "Remote Desktop",
        "label": "Require Network Level Authentication for RDP",
        "kind": "bool",
    },
    "removable_storage_write_protect": {
        "category": "USB & Storage",
        "label": "Deny write access to removable disks",
        "kind": "bool",
    },
    "hide_last_signed_in_user": {
        "category": "Screen Lock",
        "label": "Hide the last signed-in user on the sign-in screen",
        "kind": "bool",
    },
    "lock_screen_camera_enabled": {
        "category": "Screen Lock",
        "label": "Allow camera access from the lock screen",
        "kind": "bool",
    },
    "lock_screen_slideshow_enabled": {
        "category": "Screen Lock",
        "label": "Allow the lock screen slideshow",
        "kind": "bool",
    },
    "windows_update_auto_restart_with_users_logged_in": {
        "category": "Windows Update",
        "label": "Allow automatic restart for updates while users are signed in",
        "kind": "bool",
    },
    "windows_update_defer_feature_updates_days": {
        "category": "Windows Update",
        "label": "Defer feature updates (days)",
        "kind": "int",
        "min": 0,
        "max": 365,
    },
    "defender_cloud_delivered_protection_enabled": {
        "category": "Security",
        "label": "Windows Defender cloud-delivered protection",
        "kind": "bool",
    },
    "defender_scan_removable_drives_enabled": {
        "category": "Security",
        "label": "Scan removable drives with Windows Defender",
        "kind": "bool",
    },
    "powershell_script_block_logging_enabled": {
        "category": "Security",
        "label": "PowerShell script block logging",
        "kind": "bool",
    },
    "windows_script_host_enabled": {
        "category": "Security",
        "label": "Windows Script Host (.vbs/.js execution)",
        "kind": "bool",
    },
    "remote_registry_service_enabled": {
        "category": "Security",
        "label": "Remote Registry service",
        "kind": "bool",
    },
    "remote_assistance_enabled": {
        "category": "Security",
        "label": "Allow Remote Assistance",
        "kind": "bool",
    },
    "telemetry_level": {
        "category": "Privacy",
        "label": "Diagnostic data (telemetry) level",
        "kind": "enum",
        "options": ["Security", "Basic", "Enhanced", "Full"],
        "help": "\"Security\" requires Enterprise/Education — silently behaves as Basic elsewhere.",
    },
    "cortana_enabled": {
        "category": "Privacy",
        "label": "Allow Cortana",
        "kind": "bool",
    },
    "onedrive_sync_enabled": {
        "category": "Privacy",
        "label": "Allow OneDrive file sync",
        "kind": "bool",
    },
    "windows_spotlight_enabled": {
        "category": "Privacy",
        "label": "Windows Spotlight (lock screen suggestions/tips)",
        "kind": "bool",
    },
    "windows_store_enabled": {
        "category": "Privacy",
        "label": "Microsoft Store",
        "kind": "bool",
    },
    "llmnr_enabled": {
        "category": "Security",
        "label": "Link-Local Multicast Name Resolution (LLMNR)",
        "kind": "bool",
    },
}


def _load_admx_catalog():
    """Load the ADMX-derived catalog generated by
    scripts/extract-admx-catalog.ps1 + filter_admx_catalog.py into the same
    {key: {category, label, kind, min, max, options}} shape as
    HAND_PICKED_SETTINGS, so both tiers can be validated/displayed
    uniformly. Upstream ships an empty catalog; see docs/POLICY_CATALOG.md."""
    path = pathlib.Path(__file__).parent / "policy_catalog.json"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    catalog = {}
    for e in entries:
        meta = {
            "category": e["category"],
            "label": e["label"],
            "kind": e["kind"],
            "admx": True,  # UI marker: this came from the bulk ADMX import, not hand-review
            "scope": e.get("scope", "unknown"),
        }
        if e.get("help"):
            meta["help"] = e["help"]
        if e.get("readonly"):
            meta["readonly"] = True
        if e["key"] in {
            "laps_adpasswordencryptionenabled",
            "laps_adpasswordencryptionprincipal_text_adpasswordencryptionprincipal",
            "laps_adencryptedpasswordhistorysize_laps_adencryptedpasswordhistorysize_int",
            "laps_adbackupdsrmpassword",
        }:
            meta["requires_ad"] = True
        if e["kind"] == "int":
            meta["min"] = e["min"]
            meta["max"] = e["max"]
        elif e["kind"] == "enum":
            meta["options"] = [opt["label"] for opt in e["options"]]
        catalog[e["key"]] = meta
    return catalog


ADMX_SETTINGS = _load_admx_catalog()
POLICY_SETTINGS = {**HAND_PICKED_SETTINGS, **ADMX_SETTINGS}


def validate_setting_value(key, value):
    """Raise ValueError if key is unknown or value doesn't fit its kind/range/enum."""
    meta = POLICY_SETTINGS.get(key)
    if not meta:
        raise ValueError(f"unknown policy setting: {key}")
    if meta.get("readonly"):
        raise ValueError(f"{key}: this setting is status-only and cannot be pushed")
    kind = meta["kind"]
    if key == "windows_firewall_rules":
        _validate_firewall_rules_json(value)
        return True
    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{key}: expected a boolean value")
    elif kind == "int":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError(f"{key}: expected a numeric value")
        if not (meta["min"] <= value <= meta["max"]):
            raise ValueError(f"{key}: value out of range [{meta['min']}, {meta['max']}]")
    elif kind == "enum":
        if value not in meta["options"]:
            raise ValueError(f"{key}: value not one of {meta['options']}")
    elif kind == "string":
        if not isinstance(value, str):
            raise ValueError(f"{key}: expected a string value")
    return True


def validate_settings_dict(settings):
    """Validate a whole {key: value} PUSH_LOCAL_POLICY settings payload."""
    if not isinstance(settings, dict) or not settings:
        raise ValueError("settings must be a non-empty object")
    for key, value in settings.items():
        validate_setting_value(key, value)
    return True
