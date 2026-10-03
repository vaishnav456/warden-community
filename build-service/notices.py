"""Offline notice bundle for downloadable agents. Missing notices fail a build."""
import json
from pathlib import Path


def agent_notice_bundle(root: Path, go_license: Path) -> dict[str, bytes]:
    root = root.resolve(strict=True)

    def read(relative):
        path = root / relative
        # No external files, directory links or symlink escapes in a release.
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
            raise ValueError("Notice path escapes the notice source")
        raw = path.read_bytes()
        if not 32 <= len(raw) <= 1024 * 1024:
            raise ValueError("Notice file has an invalid size")
        return raw

    inventory = json.loads(read("third_party/inventory.json"))
    credits = read("THIRD_PARTY_NOTICES.md")
    parts = [b"Warden agent third-party license texts\n"
             b"This includes the declared Go dependency set, a conservative superset.\n"
             b"For versions, credits and additional release obligations see THIRD_PARTY_NOTICES.md.\n"]
    entries = [item for item in inventory["dependencies"] if item["ecosystem"] == "go"]
    if not entries:
        raise ValueError("Go license inventory is empty")
    seen = set()
    for item in entries:
        if not item.get("license_files"):
            raise ValueError("Go dependency has no license texts")
        for notice in item["license_files"]:
            relative = notice["path"]
            if not relative.startswith("third_party/licenses/go/"):
                raise ValueError("Invalid Go notice location")
            if relative in seen:
                continue
            seen.add(relative)
            label = f"\n\n--- {item['name']} @ {item['version']} / {relative} ---\n"
            parts.extend((label.encode("utf-8"), read(relative)))
    toolchain = go_license.read_bytes()
    if not 32 <= len(toolchain) <= 1024 * 1024:
        raise ValueError("Missing Go toolchain license")
    parts.extend((b"\n\n--- Go standard library / toolchain LICENSE ---\n", toolchain))
    licenses = b"".join(parts)
    if len(licenses) > 8 * 1024 * 1024:
        raise ValueError("Agent notice bundle exceeds its size limit")
    return {"THIRD_PARTY_NOTICES.md": credits, "THIRD_PARTY_LICENSES.txt": licenses}
