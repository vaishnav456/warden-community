"""Read-only backup manifest and encrypted key-probe validation.

This complements, but does not replace, an isolated database/application restore.
Never log a backup file, decryption key or decrypted probe.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b'warden-recovery-probe-v1'


def verify(root, manifest, key):
    root = Path(root).resolve()
    if len(key) != 32 or manifest.get('version') != 1:
        raise ValueError('Invalid recovery manifest or probe key')
    entries = manifest.get('files')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 10000:
        raise ValueError('Invalid recovery file count')
    seen = set()
    for entry in entries:
        relative = Path(entry['path'])
        path = root / relative
        if (relative.is_absolute() or '..' in relative.parts or relative in seen
                or not path.resolve().is_relative_to(root) or path.resolve() != path.absolute()
                or not path.is_file()):
            raise ValueError('Invalid recovery file reference')
        seen.add(relative)
        digest = hashlib.sha256()
        size = 0
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
                size += len(block)
        if digest.hexdigest() != entry['sha256'] or size != entry['bytes']:
            raise ValueError('Recovery file verification failed')
    probe = base64.b64decode(manifest['encrypted_probe'], validate=True)
    if not 28 <= len(probe) <= 65536:
        raise ValueError('Invalid recovery key probe')
    plain = AESGCM(key).decrypt(probe[:12], probe[12:], AAD)
    if hashlib.sha256(plain).hexdigest() != manifest['probe_sha256']:
        raise ValueError('Recovery key probe verification failed')
    return dict(files_verified=len(entries), hashes='passed', key_probe='passed',
                application_restore='required separately')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--manifest', required=True)
    args = parser.parse_args()
    try:
        key = base64.b64decode(os.environ['WARDEN_RECOVERY_PROBE_KEY_B64'], validate=True)
        document = json.loads(Path(args.manifest).read_text())
        print(json.dumps(verify(args.root, document, key), indent=2))
    except Exception:
        # Detailed file/provider errors can disclose private paths or content.
        parser.exit(1, 'Recovery validation failed; inspect the bundle in the protected recovery environment.\n')
