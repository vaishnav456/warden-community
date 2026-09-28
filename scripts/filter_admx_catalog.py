"""
filter_admx_catalog.py — turns the raw ADMX extraction (admx-catalog.json,
one entry per <policy> element straight from Microsoft's own ADMX files)
into a normalized catalog Warden can actually use: bool/int/enum/string
settings with a concrete registry key + value name + type, matching the
kind model policy.go/policy_settings.py already use.

Filters out policies that don't fit that model cleanly:
  - list/multiText elements (free-form, unbounded lists — not a single
    validated value)
  - policies with no valueName at all anywhere (some ADMX policies only
    ever set values via child elements with their own keys, one level
    deeper than this pass handles)
  - obviously server/domain-only categories (best-effort name filter)

Run standalone to see the resulting shape/counts before wiring it into the
real import.
"""
import json
import re
import sys
from collections import Counter

# Curated allowlist (exact ADMX category names) — chosen after inspecting
# the full 202-category breakdown of this machine's ADMX set. Everything
# else (Internet Explorer's 937-policy "inetres", App-V, UE-V, MMC snap-in
# restrictions, ActiveX, most server/domain-controller-only categories,
# etc.) is left out — real, disruptive, or just not relevant to a general
# Windows fleet tool. Add more categories later on request.
ALLOWED_CATEGORIES = {
    "WindowsUpdate", "WindowsDefender", "WindowsDefenderSecurityCenter",
    "WindowsFirewall", "TerminalServer", "StartMenu", "WindowsExplorer",
    "Explorer", "Power", "Search", "OfflineFiles", "GroupPolicy",
    "Printing", "Printing2", "ErrorReporting", "RemovableStorage",
    "UserProfiles", "WindowsMediaPlayer", "SmartScreen", "AutoPlay",
    "CtrlAltDel", "DataCollection", "CloudContent", "RemoteAssistance",
    "LAPS", "AttachmentManager", "DeviceInstallation",
    "WindowsRemoteManagement", "NetworkConnections", "TaskScheduler",
    "EventLog", "Smartcard", "CredentialProviders",
    "VolumeEncryption",  # BitLocker -- see READONLY_CATEGORIES below
}

# Categories whose settings are exposed as status-only: shown (readable via
# CHECK_POLICY_DRIFT) but never pushable. BitLocker enforcement is a
# disruptive, hard-to-reverse operation with recovery-key-escrow decisions
# that don't reduce to a simple toggle -- same reasoning that already kept
# it out of the original hand-picked catalog entirely. Read-only status
# ("is this drive encrypted") is safe; flipping it on/off from a checkbox
# is not, so the whole category stays read-only rather than trying to
# cherry-pick which of its ~150 policies are "safe enough" to push.
READONLY_CATEGORIES = {"VolumeEncryption"}


def clean_help_text(text):
    if not text:
        return None
    # ADML explainText is often long, multi-paragraph, with irregular
    # line breaks -- collapse to a single line and cap length for a tooltip.
    collapsed = " ".join(text.split())
    return collapsed[:400]


def normalize_supported_on(raw):
    # NOTE: despite the name, ADMX's supportedOn overwhelmingly encodes which
    # Windows VERSION introduced a policy (Vista/7/8/10/11, specific builds)
    # -- not which SKU/edition (Home/Pro/Enterprise) supports it. There's no
    # reliable per-policy Home/Pro/Enterprise signal in this data for the
    # vast majority of entries, so this is surfaced as an "OS version" note,
    # not an edition badge. The one edition distinction Warden actually
    # enforces (Remote Desktop hosting requires Pro/Enterprise/Education,
    # never Home) is a hardcoded, independently-verified check in
    # agent-go/policy.go's isHomeEdition(), not derived from this field.
    if not raw:
        return "unknown"
    return raw.split(":")[-1].replace("SUPPORTED_", "")


def convert_entry(raw):
    """Return a list of normalized {key, label, category, kind, ...} dicts —
    a policy with multiple elements can produce multiple settings."""
    out = []
    cat = raw.get("category", "")
    if cat not in ALLOWED_CATEGORIES:
        return out

    # The agent's parameterized policy engine writes HKLM.  ADMX User-class
    # policies require HKCU/MLGPO processing and must never be silently
    # redirected into HKLM.  User policy remains available through reviewed
    # LGPO templates until a per-user MLGPO executor is added.
    policy_class = str(raw.get("policyClass") or "").lower()
    if policy_class != "machine":
        return out

    base_key = raw.get("registryKey")
    supported = normalize_supported_on(raw.get("supportedOn"))
    help_text = clean_help_text(raw.get("explainText"))
    readonly = cat in READONLY_CATEGORIES
    label = raw.get("displayName") or raw["name"]

    def make_key(suffix=None):
        name = raw["name"] if not suffix else f'{raw["name"]}_{suffix}'
        return re.sub(r'[^a-zA-Z0-9_]', '_', name).lower()

    def base_fields(key, kind):
        f = {
            "key": key,
            "label": label,
            "category": cat,
            "kind": kind,
            "registryKey": base_key,
            "scope": "machine",
            "supportedOn": supported,
        }
        if help_text:
            f["help"] = help_text
        if readonly:
            f["readonly"] = True
        return f

    # Simple top-level boolean (no elements at all)
    if raw.get("type") == "boolean" and raw.get("valueName") and not raw.get("elements"):
        entry = base_fields(make_key(), "bool")
        entry["valueName"] = raw["valueName"]
        entry["regType"] = "dword"
        out.append(entry)
        return out

    for el in raw.get("elements") or []:
        kind = el.get("kind")
        value_name = el.get("valueName")
        if not value_name:
            continue
        if kind == "decimal":
            entry = base_fields(make_key(el.get("id")), "int")
            entry.update({
                "valueName": value_name,
                "regType": "dword",
                "min": int(el.get("min") or 0),
                "max": int(el.get("max") or 999999),
            })
            out.append(entry)
        elif kind == "boolean":
            entry = base_fields(make_key(el.get("id")), "bool")
            entry.update({"valueName": value_name, "regType": "dword"})
            out.append(entry)
        elif kind == "enum":
            items = el.get("items") or []
            if not items:
                continue
            # ADMX <item><value> is either <decimal> (a real numeric
            # registry DWORD) or <string> (REG_SZ, even though it's still
            # an enum choice -- drive letters, GUIDs, "Enabled"/"Block"/
            # etc). extract-admx-catalog.ps1 records which one this
            # element actually used as valueType -- getting this wrong
            # means every push of the setting fails trying to parse a
            # GUID or "Block" as a base-10 integer.
            reg_type = "string" if el.get("valueType") == "string" else "dword"
            entry = base_fields(make_key(el.get("id")), "enum")
            entry.update({
                "valueName": value_name,
                "regType": reg_type,
                "options": [{"label": i["label"], "value": i["value"]} for i in items],
            })
            out.append(entry)
        elif kind == "text":
            entry = base_fields(make_key(el.get("id")), "string")
            entry.update({"valueName": value_name, "regType": "string"})
            out.append(entry)
        # list / multiText: intentionally skipped (free-form, unbounded)
    return out


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "admx-catalog.json"
    with open(src, encoding="utf-8-sig") as f:
        raw_policies = json.load(f)

    normalized = []
    for raw in raw_policies:
        normalized.extend(convert_entry(raw))

    kind_counts = Counter(e["kind"] for e in normalized)
    cat_counts = Counter(e["category"] for e in normalized)

    print(f"Raw ADMX policies: {len(raw_policies)}")
    print(f"Normalized settings after filtering: {len(normalized)}")
    print(f"By kind: {dict(kind_counts)}")
    print(f"Distinct categories: {len(cat_counts)}")
    print("Top 20 categories by setting count:")
    for cat, count in cat_counts.most_common(20):
        print(f"  {cat}: {count}")

    with open("policy_catalog_normalized.json", "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2)
    print("Saved policy_catalog_normalized.json")


if __name__ == "__main__":
    main()
