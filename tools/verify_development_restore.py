"""Restore a synthetic database inside a labelled, network-isolated test container."""
import argparse
import hashlib
import json
import subprocess
import uuid


def command(*arguments, data=None):
    return subprocess.run(list(arguments), input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=60).stdout


def verify(container):
    metadata = json.loads(command('docker', 'inspect', container))[0]
    if (metadata['Config'].get('Labels', {}).get('com.warden.test') != 'operational-foundations'
            or metadata['HostConfig']['NetworkMode'] != 'none'
            or '/var/lib/postgresql/data' not in metadata['HostConfig'].get('Tmpfs', {})
            or any(mount['Destination'].startswith('/var/lib/postgresql/data')
                   and mount['Type'] != 'tmpfs' for mount in metadata.get('Mounts', []))):
        raise ValueError('Only labelled, network-isolated temporary test databases are allowed')
    restored = 'foundation_restore_' + uuid.uuid4().hex
    created = False
    def sql(database, query):
        return command('docker', 'exec', container, 'psql', '-U', 'postgres', '-d', database,
                       '-v', 'ON_ERROR_STOP=1', '-Atc', query).decode().strip()
    query = "SELECT count(*) FROM endpt.mail_events"
    source_count = sql('foundation_test', query)
    dump = command('docker', 'exec', container, 'pg_dump', '-U', 'postgres', '-d', 'foundation_test', '-Fc')
    try:
        command('docker', 'exec', container, 'createdb', '-U', 'postgres', restored)
        created = True
        command('docker', 'exec', '-i', container, 'pg_restore', '-U', 'postgres',
                '-d', restored, '--exit-on-error', data=dump)
        if sql(restored, query) != source_count:
            raise ValueError('Restored row count mismatch')
        if sql(restored, "SELECT to_regprocedure('endpt.claim_mail_event(uuid)') IS NOT NULL") != 't':
            raise ValueError('Restored claim function missing')
        return dict(restore='passed', synthetic_event_rows=int(source_count),
                    dump_sha256=hashlib.sha256(dump).hexdigest(), application_data='not used')
    finally:
        if created:
            command('docker', 'exec', container, 'dropdb', '-U', 'postgres', restored)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.container), indent=2))
    except Exception:
        parser.exit(1, 'Isolated restore verification failed. No application database was selected.\n')
