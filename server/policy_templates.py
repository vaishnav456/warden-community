"""Warden-authored starter policies.

The upstream repository intentionally avoids redistributing third-party
benchmark text or generated vendor policy catalogs. These settings are a
reviewable operational starting point, not a compliance certification.
"""

POLICY_TEMPLATES = {}


WARDEN_WINDOWS_SECURE_BASELINE = {
    "guest_account_enabled": False,
    "require_ctrl_alt_del": True,
    "hide_last_signed_in_user": True,
    "screen_lock_timeout_minutes": 15,
    "lock_screen_camera_enabled": False,
    "lock_screen_slideshow_enabled": False,
    "firewall_all_profiles_enabled": True,
    "defender_realtime_protection_enabled": True,
    "defender_cloud_delivered_protection_enabled": True,
    "defender_scan_removable_drives_enabled": True,
    "smartscreen_enabled": True,
    "powershell_execution_policy": "RemoteSigned",
    "powershell_script_block_logging_enabled": True,
    "windows_update_auto_download": True,
    "windows_update_auto_restart_with_users_logged_in": False,
    "autorun_enabled": False,
    "remote_registry_service_enabled": False,
    "remote_assistance_enabled": False,
    "rdp_network_level_auth_required": True,
    "llmnr_enabled": False,
}


POLICY_BENCHMARKS = {
    "warden_windows_secure_baseline": {
        "name": "Warden Windows Secure Baseline",
        "provider": "Warden Community",
        "version": "2026.1",
        "profile": "Reviewable starter",
        "source_url": "",
        "coverage": (
            "Configures supported sign-in, firewall, Defender, PowerShell, "
            "update, remote-access, and local attack-surface controls. "
            "Tailor and validate it for your organization before deployment."
        ),
        "description": (
            "A Warden-authored secure starting point built only from the "
            "reviewed settings shipped in this repository."
        ),
        "settings": WARDEN_WINDOWS_SECURE_BASELINE,
        "checks": [
            "bitlocker_enabled",
            "firewall_enabled",
            "antivirus_present",
            "screen_lock_enabled",
            "auto_update_enabled",
            "guest_account_disabled",
        ],
    },
}
