"""Warden private device PKI.

Public HTTPS and device identity are deliberately separate. Cloudflare or
Let's Encrypt protects the public hostname; this module issues short-lived
private certificates to enrolled endpoints and Warden Home nodes. Device
private keys never leave their device and there is no per-device SaaS quota.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import tempfile
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import config

log = logging.getLogger("warden.agent_ca")
_LOCK = threading.Lock()
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")


def _paths() -> dict[str, Path]:
    base = Path(config.DEVICE_CA_DIR)
    return {
        "base": base,
        "root_key": base / "root-ca.key.pem",
        "root_cert": base / "root-ca.crt.pem",
        "issuer_key": base / "issuing-ca.key.pem",
        "issuer_cert": base / "issuing-ca.crt.pem",
    }


def _atomic_private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _write_public(path: Path, data: bytes) -> None:
    _atomic_private_write(path, data)
    os.chmod(path, 0o644)


def _new_ca(subject: str, *, issuer_cert=None, issuer_key=None, years=10, path_length=1):
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Warden Device PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name)
               .issuer_name(issuer_cert.subject if issuer_cert else name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5))
               .not_valid_after(now + timedelta(days=365 * years))
               .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=True, key_encipherment=False,
                   content_commitment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=True, crl_sign=True,
                   encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    signer = issuer_key or key
    if issuer_cert:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    return key, builder.sign(signer, hashes.SHA384())


def ensure_device_ca() -> None:
    """Create the CA once, or fail if its durable state is incomplete."""
    paths = _paths()
    with _LOCK:
        # root-ca.key.pem is needed only to create/replace the issuing CA. It
        # may be moved to offline custody after bootstrap; routine leaf
        # issuance needs only the root certificate and issuing keypair.
        names = ("root_cert", "issuer_key", "issuer_cert")
        present = [paths[name].exists() for name in names]
        if all(present):
            _load_ca()
            return
        if any(present):
            raise RuntimeError("Warden device CA is incomplete; restore it from backup")
        if not config.DEVICE_CA_AUTO_BOOTSTRAP:
            raise RuntimeError("Warden device CA is not provisioned and automatic bootstrap is disabled")
        paths["base"].mkdir(parents=True, exist_ok=True, mode=0o700)
        root_key, root_cert = _new_ca("Warden Device Root CA", years=15, path_length=1)
        issuer_key, issuer_cert = _new_ca(
            "Warden Device Issuing CA", issuer_cert=root_cert, issuer_key=root_key,
            years=5, path_length=0,
        )
        private_format = serialization.PrivateFormat.PKCS8
        encryption = serialization.NoEncryption()
        _atomic_private_write(paths["root_key"], root_key.private_bytes(
            serialization.Encoding.PEM, private_format, encryption))
        _atomic_private_write(paths["issuer_key"], issuer_key.private_bytes(
            serialization.Encoding.PEM, private_format, encryption))
        _write_public(paths["root_cert"], root_cert.public_bytes(serialization.Encoding.PEM))
        _write_public(paths["issuer_cert"], issuer_cert.public_bytes(serialization.Encoding.PEM))
        log.warning("Created Warden device CA in %s; back it up and protect the root key", paths["base"])


def _load_ca():
    paths = _paths()
    root = x509.load_pem_x509_certificate(paths["root_cert"].read_bytes())
    issuer = x509.load_pem_x509_certificate(paths["issuer_cert"].read_bytes())
    issuer_key = serialization.load_pem_private_key(paths["issuer_key"].read_bytes(), password=None)
    if issuer.issuer != root.subject or issuer_key.public_key().public_numbers() != issuer.public_key().public_numbers():
        raise RuntimeError("Warden device CA certificate/key validation failed")
    return root, issuer, issuer_key


def ca_bundle_pem() -> str:
    ensure_device_ca()
    root, issuer, _ = _load_ca()
    return (issuer.public_bytes(serialization.Encoding.PEM)
            + root.public_bytes(serialization.Encoding.PEM)).decode()


def _validated_csr(csr_pem: str) -> x509.CertificateRequest:
    if not csr_pem or len(csr_pem) > 32_000:
        raise ValueError("invalid CSR size")
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    return csr


def _identity_uri(kind: str, company_id: str, identity_id: str):
    if kind not in {"endpoint", "home-node"}:
        raise ValueError("invalid device kind")
    for value in (str(company_id), str(identity_id)):
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("invalid device identity")
    return x509.UniformResourceIdentifier(f"spiffe://warden/{kind}/{company_id}/{identity_id}")


def _issue(csr_pem: str, *, kind: str, company_id: str, identity_id: str,
           common_name: str, server_names=(), validity_days=None):
    ensure_device_ca()
    _, issuer, issuer_key = _load_ca()
    csr = _validated_csr(csr_pem)
    days = max(1, min(int(validity_days or config.DEVICE_CERT_VALIDITY_DAYS), 30))
    clock_skew_hours = max(0, min(int(config.DEVICE_CERT_CLOCK_SKEW_HOURS), 24))
    now = datetime.now(timezone.utc)
    names: list[x509.GeneralName] = [_identity_uri(kind, company_id, identity_id)]
    for value in server_names:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            names.append(x509.DNSName(value.encode("idna").decode("ascii")))
    usages = [ExtendedKeyUsageOID.CLIENT_AUTH]
    if kind == "home-node":
        usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
    certificate = (x509.CertificateBuilder()
                   .subject_name(x509.Name([
                       x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Warden"),
                       x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64]),
                   ])).issuer_name(issuer.subject).public_key(csr.public_key())
                   .serial_number(x509.random_serial_number())
                   # Managed endpoints can return from snapshots or long
                   # sleep with a stale clock. Backdating only affects when
                   # the new leaf becomes usable; its expiry remains now +
                   # the configured short lifetime.
                   .not_valid_before(now - timedelta(hours=clock_skew_hours))
                   .not_valid_after(now + timedelta(days=days))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, key_encipherment=isinstance(csr.public_key(), rsa.RSAPublicKey),
                       content_commitment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=False, crl_sign=False,
                       encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage(usages), critical=True)
                   .add_extension(x509.SubjectAlternativeName(names), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       issuer_key.public_key()), critical=False)
                   .sign(issuer_key, hashes.SHA384()))
    leaf = certificate.public_bytes(serialization.Encoding.PEM)
    chain = leaf + issuer.public_bytes(serialization.Encoding.PEM)
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    return chain.decode(), fingerprint, f"local:{certificate.serial_number:x}", certificate.not_valid_after_utc


def sign_agent_csr(csr_pem: str, endpoint_id: str, *, company_id="unknown", validity_days=None):
    cert, fingerprint, reference, _ = _issue(
        csr_pem, kind="endpoint", company_id=str(company_id), identity_id=str(endpoint_id),
        common_name=f"Warden endpoint {endpoint_id}", validity_days=validity_days,
    )
    return cert, fingerprint, reference


def sign_home_node_csr(csr_pem: str, node: dict):
    hosts = set()
    for field in ("local_url", "public_url"):
        parsed = urllib.parse.urlparse(str(node.get(field) or ""))
        if parsed.hostname:
            hosts.add(parsed.hostname)
    if node.get("deployment_mode") == "p2p":
        hosts.add(f"warden-home-{node['id']}.internal")
    if not hosts:
        raise ValueError("Home Node has no registered HTTPS hostname or IP")
    return _issue(
        csr_pem, kind="home-node", company_id=str(node["company_id"]),
        identity_id=str(node["id"]), common_name=f"Warden Home {node['id']}",
        server_names=sorted(hosts),
    )


def revoke_agent_cert(certificate_reference: str) -> None:
    """Local leafs expire quickly; DB/grant revocation denies them immediately."""
    if not certificate_reference or certificate_reference.startswith("local:"):
        return
    log.warning("Legacy external certificate %s requires provider-side revocation", certificate_reference)


def certificate_metadata(cert_pem: str) -> dict:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return {
        "fingerprint": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": f"{cert.serial_number:x}",
    }
