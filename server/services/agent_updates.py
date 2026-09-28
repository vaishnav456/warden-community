"""Immutable, authenticated artifacts used by agent update jobs."""

import hashlib
import io
import zipfile

import config
import db


class AgentBuildUnavailable(RuntimeError):
    pass


def _build_archive(build):
    path = config.AGENT_DIST_DIR / str(build["id"]) / "agent-installer.zip"
    if not path.is_file():
        raise AgentBuildUnavailable("agent build archive is missing")
    return path


def _member_name(target_platform, kind):
    if kind == "agent":
        return "warden-agent.exe" if target_platform.startswith("windows-") else "warden-agent"
    if kind == "credential_provider" and target_platform.startswith("windows-"):
        return "WardenCredentialProvider.dll"
    raise AgentBuildUnavailable("artifact is not available for this platform")


def read_build_artifact(build, kind):
    target = build.get("target_platform") or "windows-amd64"
    member = _member_name(target, kind)
    limit = 100 * 1024 * 1024 if kind == "agent" else 20 * 1024 * 1024
    try:
        with zipfile.ZipFile(_build_archive(build)) as archive:
            info = archive.getinfo(member)
            if info.file_size <= 0 or info.file_size > limit:
                raise AgentBuildUnavailable("agent artifact has an invalid size")
            data = archive.read(info)
    except (KeyError, zipfile.BadZipFile, OSError) as exc:
        raise AgentBuildUnavailable("agent build archive is invalid") from exc
    if len(data) != info.file_size:
        raise AgentBuildUnavailable("agent artifact was truncated")
    return data


def update_payload(endpoint):
    """Return a build-ID-pinned update payload for one endpoint.

    Build-specific URLs avoid the race where `/latest-exe` changes between
    dispatch and download. Windows updates always include the signed
    Credential Provider companion so an already-installed service reaches
    the same state as a fresh MSI installation.
    """
    target = db.endpoint_target_platform(endpoint)
    build = db.get_latest_completed_build(target)
    if not build or not build.get("sha256") or not build.get("agent_version"):
        raise AgentBuildUnavailable("no agent build is available")

    build_id = str(build["id"])
    base = config.SERVER_URL.rstrip("/")
    payload = {
        "download_url": f"{base}/api/agent/builds/{build_id}/agent",
        "sha256": str(build["sha256"]).lower(),
        "version": build["agent_version"],
    }
    if target.startswith("windows-"):
        provider = read_build_artifact(build, "credential_provider")
        payload.update({
            "credential_provider_url": f"{base}/api/agent/builds/{build_id}/credential-provider",
            "credential_provider_sha256": hashlib.sha256(provider).hexdigest(),
        })
    return payload


def build_for_endpoint(build_id, endpoint):
    build = db.get_build_request(build_id)
    if not build or build.get("status") != "completed":
        raise AgentBuildUnavailable("agent build was not found")
    if (build.get("target_platform") or "windows-amd64") != db.endpoint_target_platform(endpoint):
        raise AgentBuildUnavailable("agent build platform does not match this endpoint")
    return build


def as_download(build, kind):
    data = read_build_artifact(build, kind)
    target = build.get("target_platform") or "windows-amd64"
    if kind == "credential_provider":
        return io.BytesIO(data), "WardenCredentialProvider.dll"
    return io.BytesIO(data), "warden-agent.exe" if target.startswith("windows-") else "warden-agent"
