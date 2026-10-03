"""Check declared dependency coverage and local notice files; no network access."""
import json
from pathlib import Path
import re
import sys


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def check(root):
    inventory = json.loads((root / "third_party/inventory.json").read_text(encoding="utf-8"))
    entries = inventory["dependencies"]
    covered = {(entry["ecosystem"], normalized(entry["name"]), entry["version"]) for entry in entries}
    errors = []
    for entry in entries:
        files = entry.get("license_files") or []
        if not files:
            errors.append("No notice files: " + entry["name"])
        for notice in files:
            path = (root / notice["path"]).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file() or path.stat().st_size < 32:
                errors.append("Missing or invalid notice file: " + notice["path"])
    for module in ("agent-go", "agent-posix", "home-node"):
        text = (root / module / "go.mod").read_text(encoding="utf-8")
        for name, version in re.findall(r"^\s+([^\s]+)\s+(v[^\s]+)", text, re.MULTILINE):
            if ("go", normalized(name), version) not in covered:
                errors.append(f"Missing declared Go dependency: {module}: {name}@{version}")
    for service in ("server", "build-service"):
        text = (root / service / "requirements.txt").read_text(encoding="utf-8")
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s#]+)", text, re.MULTILINE):
            if ("python", normalized(name), version) not in covered:
                errors.append(f"Missing pinned Python dependency: {service}: {name}=={version}")
    for asset in ("alpine", "htmx", "chartjs", "tailwindcss"):
        if not (root / "server/static/vendor/licenses" / (asset + ".txt")).is_file():
            errors.append("Missing packaged browser license: " + asset)
    for font in ("inter", "jetbrains-mono"):
        if not (root / "server/static/fonts" / font / "LICENSE.txt").is_file():
            errors.append("Missing packaged font license: " + font)
    if errors:
        raise ValueError("\n".join(errors))
    return len(entries)


if __name__ == "__main__":
    try:
        count = check(Path(__file__).resolve().parents[1])
    except (ValueError, KeyError, OSError) as error:
        print("Third-party notice check failed:\n" + str(error), file=sys.stderr)
        sys.exit(1)
    print(f"Third-party notice coverage passed: {count} inventory entries. Not a legal or artifact compliance certification.")
