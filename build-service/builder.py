"""
builder.py — Go Cross-Compile Build Pipeline
-----------------------------------------
Handles the complete build pipeline for a Warden agent installer:
  1. Write tenant-specific config.json into a per-build scratch directory.
  2. Cross-compile agent-go (GOOS=windows GOARCH=amd64) to warden-agent.exe.
  3. Package exe + config.json into a dated zip file.
  4. Upload zip to the Warden server via multipart POST.
  5. Clean up intermediate build artifacts.

Cross-compiling the Go agent needs nothing Windows-specific — it's pure Go
(no cgo, no .syso/.rc resource embedding), the same way the Python agent
build needed a native Windows box for PyInstaller. This is why build-service
now runs in a plain Linux container instead of requiring its own dedicated
Windows machine.

All subprocess calls use list args. shell=True is never used.

Output filename format: warden-{company_slug}-{branch_slug}-{YYYYMMDD}.zip
"""

import os
import re
import subprocess
import pathlib
import zipfile
import datetime
import hashlib
import base64
import logging
import json
import shutil
import traceback
from xml.sax.saxutils import escape as xml_escape

import requests   # OK here — build service machine, not agent

import config
import db

log = logging.getLogger("builder")


def write_agent_config(build_request: dict, dist_dir: pathlib.Path) -> pathlib.Path:
    """Write the tenant-specific config.json into this build's scratch dir.

    Unlike the old PyInstaller path, the Go binary never reads config.json
    at compile time (it's loaded by the deployed agent at runtime) — this
    only needs to exist so package_zip() can bundle it alongside the exe.
    """
    cfg = build_request.get("config_json", {})
    dest = dist_dir / "config.json"
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    log.info("Wrote agent config.json for build %s", build_request["id"])
    return dest


def run_go_build(build_request: dict, dist_dir: pathlib.Path,
                 credential_provider_sha256: str = "") -> pathlib.Path:
    """Cross-compile agent-go to warden-agent.exe for Windows.

    Mirrors agent-go/build.bat's own flags exactly (GOOS/GOARCH/CGO_ENABLED,
    the same -ldflags -X pins). Passing the pins here is redundant in the
    common case — install.bat drops a real config.json (with
    company_id/branch_id/enrollment_token) before the exe ever runs, so
    seedBuildConfig() (agent-go/config.go) no-ops — but it's cheap defense
    in depth if that file is ever missing at first run.
    """
    target = build_request.get("target_platform") or "windows-amd64"
    goos, goarch = target.split("-", 1)
    source_dir = config.AGENT_GO_SOURCE_DIR if goos == "windows" else config.AGENT_POSIX_SOURCE_DIR
    if not source_dir.exists():
        raise FileNotFoundError(f"agent source not found: {source_dir}")

    cfg = build_request.get("config_json", {})
    server_url = cfg.get("server_url", "")
    pubkey = cfg.get("server_ed25519_pubkey", "")
    fingerprint = cfg.get("cert_fingerprint", "")
    trust_mode = cfg.get("tls_trust_mode", "strict_leaf")
    if not pubkey or (trust_mode != "webpki" and not fingerprint):
        raise ValueError(
            "config_json missing server_ed25519_pubkey or required TLS trust configuration"
        )

    exe_path = dist_dir / ("warden-agent.exe" if goos == "windows" else "warden-agent")
    subsystem = "-H windowsgui " if goos == "windows" else ""
    ldflags = (
        f"{subsystem}-s -w "
        f"-X main.buildServerURL={server_url} "
        f"-X main.buildServerEd25519Pubkey={pubkey} "
        f"-X main.buildCertFingerprint={fingerprint} "
        f"-X main.buildTLSTrustMode={trust_mode}"
    )
    if goos == "windows":
        display_name_b64 = base64.urlsafe_b64encode(
            config.AGENT_DISPLAY_NAME.encode("utf-8")
        ).decode("ascii").rstrip("=")
        ldflags += f" -X main.buildServiceDisplayNameB64={display_name_b64}"
        ldflags += f" -X main.buildRequireAuthenticode={'true' if config.REQUIRE_AUTHENTICODE_UPDATES else 'false'}"
        if credential_provider_sha256:
            ldflags += f" -X main.buildCredentialProviderSHA256={credential_provider_sha256}"
    cmd = [
        config.GO_BINARY, "build", "-v",
        "-ldflags", ldflags,
        "-o", str(exe_path),
        ".",
    ]
    env = {
        **os.environ,
        "GOOS": goos,
        "GOARCH": goarch,
        "CGO_ENABLED": "0",
    }
    log.info("Cross-compiling agent for %s: %s", target, " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=str(source_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"go build failed (exit {result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )

    if not exe_path.exists():
        raise FileNotFoundError(f"warden-agent.exe not found after build: {exe_path}")
    log.info("Go build succeeded: %s", exe_path)
    return exe_path


def prepare_credential_provider(dist_dir: pathlib.Path) -> pathlib.Path:
    """Stage the SDK-built x64 Credential Provider and sign it.

    Credential Providers depend on Microsoft's credentialprovider.h ABI.
    The checked-in project must therefore be compiled with Visual Studio and
    the official Windows SDK; a Linux/MinGW approximation is deliberately not
    accepted for this security-sensitive LogonUI component.
    """
    source = config.CREDENTIAL_PROVIDER_BINARY
    if not source.is_file():
        raise FileNotFoundError(
            "Windows Credential Provider artifact is missing: "
            f"{source}. Build Release|x64 with windows-credential-provider/"
            "Build-CredentialProvider.ps1 on a Windows SDK build host first."
        )
    output = dist_dir / "WardenCredentialProvider.dll"
    shutil.copy2(source, output)
    sign_binary(output)
    log.info("Credential Provider staged and signed: %s", output)
    return output


def sha256_of(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_VERSION_RE = re.compile(r'agentVersion\s*=\s*"([^"]+)"')


def read_agent_version(build_request: dict) -> str:
    """Extract the agentVersion constant from agent-go/config.go's source.

    Not passed via -ldflags like the TLS/signing pins — it's a fixed
    build-time constant in the source itself (agent-go/config.go), so the
    simplest accurate way to know what version this build produced is to
    read it directly rather than duplicating it as separate config.
    """
    target = build_request.get("target_platform") or "windows-amd64"
    config_go = (
        config.AGENT_GO_SOURCE_DIR / "config.go"
        if target.startswith("windows-")
        else config.AGENT_POSIX_SOURCE_DIR / "main.go"
    )
    text = config_go.read_text(encoding="utf-8")
    m = _VERSION_RE.search(text)
    if not m:
        raise ValueError(f"Could not find agentVersion constant in {config_go}")
    return m.group(1)


def sign_binary(exe_path: pathlib.Path) -> None:
    """
    Authenticode-sign the built exe if a signing cert is configured.

    Uses osslsigncode (Linux-native) against a PFX file — signtool.exe's
    cert-store thumbprint mode (SIGN_CERT_THUMBPRINT) has no Linux
    equivalent at all and isn't supported here; that needs a real Windows
    signing host. If neither SIGN_PFX_PATH nor SIGN_CERT_THUMBPRINT is set,
    ships unsigned (logged as a warning, not a failure) — most deployments
    don't have a cert yet. But if SIGN_CERT_THUMBPRINT is set (Windows-only)
    or osslsigncode itself fails, that's a real error and must fail the
    build: silently shipping an unsigned exe when signing was expected to
    succeed would be a silent regression nobody would notice until
    AppLocker policies relying on the publisher cert
    (agent-go/policy.go:applocker-pin-warden-publisher) started rejecting the
    agent everywhere.
    """
    if config.SIGN_CERT_THUMBPRINT:
        raise RuntimeError(
            "SIGN_CERT_THUMBPRINT is Windows cert-store-only and has no "
            "Linux equivalent — this build-service container runs Linux. "
            "Use SIGN_PFX_PATH instead, or sign separately on a real "
            "Windows host."
        )

    if not config.SIGN_PFX_PATH:
        if config.SIGNING_REQUIRED:
            raise RuntimeError(
                "Signing is required but SIGN_PFX_PATH is not configured"
            )
        log.warning(
            "No signing cert configured (SIGN_PFX_PATH) — "
            "shipping %s UNSIGNED.", exe_path.name,
        )
        return

    signed_path = exe_path.with_name(exe_path.stem + "-signed" + exe_path.suffix)
    cmd = [
        "osslsigncode", "sign",
        "-pkcs12", config.SIGN_PFX_PATH,
        "-pass", config.SIGN_PFX_PASSWORD,
        "-n", config.AGENT_DISPLAY_NAME,
        "-h", "sha256",
        "-ts", config.SIGN_TIMESTAMP_URL,
        "-in", str(exe_path),
        "-out", str(signed_path),
    ]
    log.info("Signing %s with osslsigncode...", exe_path.name)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(
            f"osslsigncode failed (exit {result.returncode}):\n{result.stdout}\n{result.stderr}"
        )
    # osslsigncode verifies both the Authenticode digest and the signer's
    # certificate chain.  Internal deployments may deliberately use a
    # private/self-signed code-signing certificate, which is not present in
    # the container's system CA bundle.  Trust only the public certificate
    # from the exact PFX configured above for this verification; do not
    # disable verification or add the certificate to the global trust store.
    signer_ca_path = exe_path.with_name(exe_path.stem + "-signer-ca.pem")
    extract = subprocess.run(
        [
            "openssl", "pkcs12",
            "-in", config.SIGN_PFX_PATH,
            "-passin", f"pass:{config.SIGN_PFX_PASSWORD}",
            "-clcerts", "-nokeys",
            "-out", str(signer_ca_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if extract.returncode != 0:
        signed_path.unlink(missing_ok=True)
        signer_ca_path.unlink(missing_ok=True)
        raise RuntimeError(
            "Could not extract the signing certificate from the configured "
            f"PFX (exit {extract.returncode}):\n{extract.stdout}\n{extract.stderr}"
        )
    try:
        verify = subprocess.run(
            [
                "osslsigncode", "verify",
                "-CAfile", str(signer_ca_path),
                "-in", str(signed_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        signer_ca_path.unlink(missing_ok=True)
    if verify.returncode != 0:
        signed_path.unlink(missing_ok=True)
        raise RuntimeError(
            "Authenticode verification failed after signing "
            f"(exit {verify.returncode}):\n{verify.stdout}\n{verify.stderr}"
        )
    signed_path.replace(exe_path)
    log.info("Signed %s", exe_path.name)


_INSTALL_BAT = r"""@echo off
REM Warden Agent — self-install script bundled in the installer zip.
REM Must run elevated (as Administrator).
setlocal
set SCRIPT_DIR=%~dp0
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must be run as Administrator.
    exit /b 1
)

REM The agent's install command performs its own relocation/config seeding.
REM On a machine where Warden is already installed it reconnects the same
REM service in place instead of registering a second service. Protected
REM existing services require the MSI path, whose custom action runs as
REM LocalSystem; this ZIP path prints that requirement clearly if blocked.
"%SCRIPT_DIR%warden-agent.exe" install
if %errorlevel% neq 0 (
    echo Service install or reconnect failed. If Warden is already installed,
    echo run the MSI installer as Administrator so it can reconnect the protected service.
    exit /b 1
)
echo Warden Agent installed or reconnected and started.
"""


def package_zip(build_request: dict, exe_path: pathlib.Path, config_json_path: pathlib.Path,
                credential_provider_path: pathlib.Path | None = None) -> pathlib.Path:
    """Package warden-agent.exe, config.json, and a self-install script
    into a dated zip file.

    Without install.bat, the zip contained only the exe + a bootstrap
    config.json with nothing to actually copy that config into
    C:\\ProgramData\\WardenAgent (where the running agent looks for it —
    see agent-go/config.go's configPath) or register/start the Windows
    service — extracting and double-clicking warden-agent.exe as shipped
    would not enroll or install anything, requiring an undocumented
    manual procedure instead.
    """
    cfg = build_request.get("config_json") or {}
    company_slug = cfg.get("company_slug", "unknown")
    branch_slug  = cfg.get("branch_slug", "unknown")
    date_str = datetime.datetime.utcnow().strftime("%Y%m%d")
    target = build_request.get("target_platform") or "windows-amd64"
    zip_name = f"warden-{company_slug}-{branch_slug}-{target}-{date_str}.zip"
    zip_path = config.OUTPUT_DIR / zip_name

    with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
        binary_name = "warden-agent.exe" if target.startswith("windows-") else "warden-agent"
        zf.write(str(exe_path), binary_name)
        zf.write(str(config_json_path), "config.json")
        if target.startswith("windows-"):
            if credential_provider_path is None:
                raise RuntimeError("Windows installer is missing its Credential Provider DLL")
            zf.write(str(credential_provider_path), "WardenCredentialProvider.dll")
            zf.writestr("install.bat", _INSTALL_BAT)
        else:
            dependencies = ""
            if target.startswith("linux-"):
                dependencies = r'''if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update && sudo apt-get install -y scrot xdotool xclip || echo "Warning: remote-control helpers could not be installed"
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y ImageMagick xdotool xclip || echo "Warning: remote-control helpers could not be installed"
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y ImageMagick xdotool xclip || echo "Warning: remote-control helpers could not be installed"
fi
'''
            script = "#!/bin/sh\nset -eu\ncd \"$(dirname \"$0\")\"\n" + dependencies + "chmod 700 ./warden-agent\nexec sudo ./warden-agent install\n"
            info = zipfile.ZipInfo("install.sh")
            info.external_attr = 0o755 << 16
            zf.writestr(info, script)

    log.info("Packaged installer zip: %s", zip_path)
    return zip_path


_MSI_UPGRADE_CODE = "8F3A2C1D-6B4E-4F9A-9C2D-1A5E7B8C3F60"

_MSI_WXS_TEMPLATE = r"""<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*"
           Name="{agent_name}"
           Language="1033"
           Version="{version}"
           Manufacturer="{manufacturer}"
           UpgradeCode="{upgrade_code}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" />

    <MajorUpgrade AllowSameVersionUpgrades="yes"
                  DowngradeErrorMessage="A newer version of {agent_name} is already installed." />

    <Media Id="1" Cabinet="warden.cab" EmbedCab="yes" />

    <!-- Hides this product from Programs and Features / Apps and Features:
         no discoverable "Uninstall" button for a local user to click.
         Also see: this MSI never owns the real running service or the
         tamper-protected C:\ProgramData\WardenAgent directory at all (see
         RunAgentInstall below and the module docstring); a "staging"
         copy is all Windows Installer ever tracks, so even msiexec /x
         run directly against this file structurally cannot touch the
         real agent. -->
    <Property Id="ARPSYSTEMCOMPONENT" Value="1" />
    <Property Id="ARPNOMODIFY" Value="1" />

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="WardenAgentInstaller">
          <Component Id="StagingFiles" Guid="*">
            <File Id="AgentExe" Source="warden-agent.exe" KeyPath="yes" />
            <File Id="ConfigJson" Source="config.json" />
            <File Id="CredentialProviderDll" Source="WardenCredentialProvider.dll" />
          </Component>
        </Directory>
      </Directory>
    </Directory>

    <Feature Id="MainFeature" Title="{agent_name}" Level="1">
      <ComponentRef Id="StagingFiles" />
    </Feature>

    <!-- Runs the SAME "install" command install.bat has always run. The
         copying-config-into-dataDir step install.bat used to do in batch
         script form now lives in agent-go itself (service.go's
         selfRelocateAndSeedConfig(), called from main.go's "install" case
         before installService()); every install path (MSI staging
         directory, an extracted zip, anywhere) gets that behavior for
         free without this custom action needing to replicate any
         file-copying logic of its own. Two earlier approaches were tried
         and reverted here: (1) a bare FileKey+ExeCommand="install" with no
         Go-side copy logic left the service pointing at this transient
         staging exe with no config ever copied into dataDir; confirmed
         live (deployed agent stuck permanently unenrolled); (2) routing
         through cmd.exe + a staged run-install.bat via wixl's two-step
         Property/SetProperty pattern compiled correctly but failed at
         runtime with MSI error 1721 ("program could not be run");
         property-resolved EXE_PROPERTY custom actions expect Source to be
         a bare application path, not a combined "path + arguments"
         string, which wixl's minimal support doesn't handle any more
         gracefully than an outright unsupported combination would.
         Deferred + Impersonate="no" is what makes this run as LocalSystem
         instead of the installing user's own (possibly non-admin-enough,
         and non-SYSTEM) context: the copy into ProgramData and the
         service registration both need full SYSTEM rights. -->
    <CustomAction Id="RunAgentInstall"
                  FileKey="AgentExe"
                  ExeCommand="install"
                  Execute="deferred"
                  Impersonate="no"
                  Return="check" />

    <InstallExecuteSequence>
      <!-- wixl (msitools' WiX-alternative compiler; no full Microsoft WiX
           toolset needed for this Linux-native build) does NOT actually
           resolve the After="InstallFiles" attribute into a real relative
           sequence number; confirmed twice by dumping the compiled MSI's
           actual InstallExecuteSequence table with msiinfo, in two
           different XML orderings: RunAgentInstall was assigned 6601 both
           times, one past InstallFinalize's fixed 6600, regardless of the
           After hint or where the <Custom> element sits in this file.
           Windows Installer then rejects that placement outright with
           error 2762 ("action must be scheduled between InstallInitialize
           and InstallFinalize"); confirmed live via a verbose msiexec
           /L*V install log showing RunAgentInstall starting only after
           InstallFinalize had already returned. Fix: wixl's WixAction
           does separately support an explicit numeric Sequence attribute
           (see wixl's wix.vala), so give it one directly: 4500, safely
           between InstallFiles (4000, fixed) and RegisterUser (6000,
           fixed). After="InstallFiles" is kept only as correct-intent
           documentation; Sequence is what actually places it. -->
      <InstallInitialize />
      <Custom Action="RunAgentInstall" After="InstallFiles" Sequence="4500">NOT REMOVE</Custom>
      <InstallFinalize />
    </InstallExecuteSequence>
  </Product>
</Wix>
"""


def _msi_version(agent_version: str) -> str:
    """MSI ProductVersion must be strictly major.minor.build (each numeric,
    build <= 65535) -- agentVersion (agent-go/config.go) isn't guaranteed
    to already be in that exact shape, so parse defensively and fall back
    to a safe default rather than fail the whole build over a version
    string cosmetic mismatch."""
    parts = re.findall(r'\d+', agent_version or "")
    if not parts:
        return "1.0.0"
    nums = [int(p) for p in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    nums[0] = min(nums[0], 255)
    nums[1] = min(nums[1], 255)
    nums[2] = min(nums[2], 65535)
    return ".".join(str(n) for n in nums)


def build_msi(build_request: dict, exe_path: pathlib.Path, config_json_path: pathlib.Path,
              agent_version: str, dist_dir: pathlib.Path,
              credential_provider_path: pathlib.Path) -> pathlib.Path:
    """Compile a real .msi via msitools' wixl (Linux-native — no Windows/
    .NET/WiX Toolset needed), so this installer can be deployed through
    GPO Software Installation, SCCM, or an Intune Win32 app -- all of
    which require an actual .msi, not a raw .exe/.bat.

    Deliberately does NOT let the MSI own the Windows service or the
    tamper-protected data directory (see _MSI_WXS_TEMPLATE's comments) --
    only a harmless staging copy, so msiexec /x can never bypass the
    tamper protection applied by the agent's own "install" command.
    """
    cfg = build_request.get("config_json") or {}
    company_slug = cfg.get("company_slug", "unknown")
    branch_slug = cfg.get("branch_slug", "unknown")
    date_str = datetime.datetime.utcnow().strftime("%Y%m%d")

    staging_dir = dist_dir / "msi-staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(str(exe_path), str(staging_dir / "warden-agent.exe"))
    shutil.copy(str(config_json_path), str(staging_dir / "config.json"))
    shutil.copy(str(credential_provider_path), str(staging_dir / "WardenCredentialProvider.dll"))

    wxs_path = dist_dir / "warden-agent.wxs"
    wxs_path.write_text(
        _MSI_WXS_TEMPLATE.format(
            version=_msi_version(agent_version),
            upgrade_code=_MSI_UPGRADE_CODE,
            agent_name=xml_escape(config.AGENT_DISPLAY_NAME, {'"': '&quot;', "'": '&apos;'}),
            manufacturer=xml_escape(config.AGENT_MANUFACTURER, {'"': '&quot;', "'": '&apos;'}),
        ),
        encoding="utf-8",
    )

    msi_name = f"warden-{company_slug}-{branch_slug}-{date_str}.msi"
    msi_path = config.OUTPUT_DIR / msi_name

    cmd = ["wixl", "-v", "-o", str(msi_path), str(wxs_path)]
    log.info("Compiling MSI: %s", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(staging_dir), capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"wixl failed (exit {result.returncode}):\n{result.stdout}\n{result.stderr}")
    if not msi_path.exists():
        raise FileNotFoundError(f"warden-agent.msi not found after wixl run: {msi_path}")

    log.info("Packaged MSI installer: %s", msi_path)
    return msi_path


def upload_msi(build_request: dict, msi_path: pathlib.Path) -> None:
    build_id = build_request["id"]
    url = f"{config.WARDEN_SERVER_URL}/api/build/{build_id}/complete-msi"
    log.info("Uploading %s to %s", msi_path.name, url)
    with open(msi_path, "rb") as f:
        resp = requests.post(
            url,
            files={"file": (msi_path.name, f, "application/x-msi")},
            data={"filename": msi_path.name},
            headers={
                "X-Build-Key": config.BUILD_SERVICE_KEY,
                "X-Build-Claim": str(build_request["claim_token"]),
            },
            timeout=120,
        )
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise ValueError(f"Server returned error: {data['error']}")
    log.info("MSI upload complete for build %s", build_id)


def upload_zip(build_request: dict, zip_path: pathlib.Path, sha256_hex: str, agent_version: str) -> None:
    """Upload the installer zip to the Warden server.

    sha256/agent_version describe the exe INSIDE the zip (not the zip
    itself) — see server/routes/build_service.py's complete(), which
    stores them so a later UPDATE_AGENT job can point at this exact build.
    """
    build_id = build_request["id"]
    url = f"{config.WARDEN_SERVER_URL}/api/build/{build_id}/complete"
    log.info("Uploading %s to %s", zip_path.name, url)

    with open(zip_path, "rb") as f:
        resp = requests.post(
            url,
            files={"file": (zip_path.name, f, "application/zip")},
            data={
                "filename": zip_path.name,
                "sha256": sha256_hex,
                "agent_version": agent_version,
            },
            headers={
                "X-Build-Key": config.BUILD_SERVICE_KEY,
                "X-Build-Claim": str(build_request["claim_token"]),
            },
            timeout=120,
        )
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise ValueError(f"Server returned error: {data['error']}")
    log.info("Upload complete for build %s", build_id)


def process_build(build_request: dict) -> None:
    """Execute the complete build pipeline for one build request."""
    build_id = build_request["id"]
    dist_dir = config.OUTPUT_DIR / str(build_id)
    try:
        dist_dir.mkdir(parents=True, exist_ok=True)
        config_json_path = write_agent_config(build_request, dist_dir)
        db.renew_build_claim(build_id, build_request["claim_token"])
        target = build_request.get("target_platform") or "windows-amd64"
        credential_provider_path = None
        credential_provider_hash = ""
        if target.startswith("windows-"):
            credential_provider_path = prepare_credential_provider(dist_dir)
            credential_provider_hash = sha256_of(credential_provider_path)
        exe_path = run_go_build(build_request, dist_dir, credential_provider_hash)
        db.renew_build_claim(build_id, build_request["claim_token"])
        if target.startswith("windows-"):
            sign_binary(exe_path)
        agent_version = read_agent_version(build_request)
        sha256_hex = sha256_of(exe_path)
        zip_path = package_zip(build_request, exe_path, config_json_path, credential_provider_path)
        db.renew_build_claim(build_id, build_request["claim_token"])
        upload_zip(build_request, zip_path, sha256_hex, agent_version)

        # MSI packaging is best-effort: it wraps the exact same exe/config
        # that just succeeded above, so a wixl/MSI-specific failure
        # shouldn't fail the whole build request (the zip/install.bat path
        # is the proven one) -- just log it and leave msi_ready unset, so
        # the download UI simply doesn't offer an MSI for this build.
        if target.startswith("windows-"):
            try:
                msi_path = build_msi(build_request, exe_path, config_json_path, agent_version, dist_dir, credential_provider_path)
                upload_msi(build_request, msi_path)
            except Exception:
                log.error("MSI packaging failed for build %s (zip build still succeeded):\n%s",
                          build_id, traceback.format_exc())

        log.info("Build %s completed: %s", build_id, zip_path.name)
    except Exception:
        err = traceback.format_exc()
        log.error("Build %s failed:\n%s", build_id, err)
        try:
            db.set_build_status(
                build_id, "failed", build_request["claim_token"], error_msg=err,
            )
        except Exception as e:
            log.error("Could not update failed status for build %s: %s", build_id, e)
    finally:
        # config.json contains a live enrollment token. Remove scratch output
        # on both success and every failure path.
        try:
            shutil.rmtree(str(dist_dir))
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("Could not clean dist dir %s: %s", dist_dir, e)
