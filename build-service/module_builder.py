"""Operator-only optional Helpdesk build; never part of a tenant/Core ZIP."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
import config
from builder import sign_binary, sha256_of
from notices import agent_notice_bundle


def build_helpdesk(output, sequence, version):
    if type(sequence) is not int or not 0 < sequence <= 2**53-1:
        raise ValueError('Use a positive increasing release sequence')
    if not re.fullmatch(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})', version):
        raise ValueError('Use a three-part numeric version')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    previous = output / 'helpdesk.json'
    if previous.exists() and json.loads(previous.read_text())['release_sequence'] >= sequence:
        raise ValueError('Release sequence must increase')
    notices = agent_notice_bundle(config.NOTICE_SOURCE_DIR, config.GO_LICENSE_PATH)
    release = str(uuid.uuid4())
    executable = output / (release + '.exe')
    try:
        subprocess.run([config.GO_BINARY, 'build', '-trimpath', '-ldflags', '-H windowsgui -s -w',
                        '-o', str(executable), './cmd/helpdesk'], cwd=str(config.AGENT_GO_SOURCE_DIR),
                       env={**os.environ, 'GOOS':'windows', 'GOARCH':'amd64', 'CGO_ENABLED':'0'},
                       check=True, timeout=300, capture_output=True)
        sign_binary(executable)
        for name, content in notices.items():
            (output / name).write_bytes(content)
        value = dict(release_id=release, release_sequence=sequence, version=version,
                     min_core_version='2.7.0', sha256=sha256_of(executable), size_bytes=executable.stat().st_size)
        temporary = output / ('helpdesk-' + release + '.pending')
        temporary.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
        temporary.replace(previous)
        return value
    except Exception:
        executable.unlink(missing_ok=True)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--sequence', required=True, type=int)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    print(json.dumps(build_helpdesk(args.output, args.sequence, args.version)))
