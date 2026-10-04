"""Explicit opt-in separation. Combined remains the deployment default."""
import os


def role():
    value = os.environ.get('WARDEN_PROCESS_ROLE', 'combined')
    if value not in {'combined','api','background','relay'}:
        raise RuntimeError('Invalid Warden process role')
    if value != 'combined' and os.environ.get('WARDEN_ALLOW_SPLIT_SERVICES','false').lower() != 'true':
        raise RuntimeError('Split services require explicit staging approval')
    return value
