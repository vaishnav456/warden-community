"""
Warden — Tamper-evident audit log service
Every row includes a SHA-256 hash chained to the previous row.
Rows are insert-only (no UPDATE/DELETE RLS policies on audit_log).
"""
import hashlib
import json
from datetime import datetime, timezone


def _compute_hash(prev_hash: str, event: str, detail: dict, ts: str) -> str:
    payload = f"{prev_hash}|{event}|{json.dumps(detail, sort_keys=True)}|{ts}"
    return hashlib.sha256(payload.encode()).hexdigest()


def write_audit(conn, *, company_id=None, branch_id=None, endpoint_id=None,
                admin_id=None, event: str, detail: dict = None,
                ip_address: str = None):
    """Insert a tamper-evident row into endpt.audit_log."""
    if detail is None:
        detail = {}
    ts = datetime.now(timezone.utc).isoformat()

    with conn.cursor() as cur:
        # Serialize writers for this chain for the duration of the transaction.
        # Row locking cannot lock an empty chain and locking the current tail
        # alone still permits branching; a transaction advisory lock covers both.
        cur.execute("SELECT pg_advisory_xact_lock(hashtext('endpt.audit_log.hash_chain'))")
        # Fetch last hash for the chain
        cur.execute(
            "SELECT row_hash FROM endpt.audit_log ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
        prev_hash = row[0] if row else ""

        row_hash = _compute_hash(prev_hash, event, detail, ts)

        cur.execute(
            """
            INSERT INTO endpt.audit_log
              (company_id, branch_id, endpoint_id, admin_id,
               event, detail, ip_address, prev_hash, row_hash, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                str(company_id) if company_id else None,
                str(branch_id) if branch_id else None,
                str(endpoint_id) if endpoint_id else None,
                str(admin_id) if admin_id else None,
                event,
                json.dumps(detail),
                ip_address,
                prev_hash,
                row_hash,
                ts,
            ),
        )
    conn.commit()


def write_escalation_audit(conn, *, event: str, actor: str, operation: str = None,
                           detail: dict = None, escalation_request_id=None,
                           saved_escalation_id=None, endpoint_id=None, company_id=None):
    """Insert into endpt.escalation_audit with chained hash."""
    if detail is None:
        detail = {}
    ts = datetime.now(timezone.utc).isoformat()

    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext('endpt.escalation_audit.hash_chain'))")
        cur.execute(
            "SELECT row_hash FROM endpt.escalation_audit ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
        prev_hash = row[0] if row else ""

        row_hash = _compute_hash(prev_hash, event, detail, ts)

        cur.execute(
            """
            INSERT INTO endpt.escalation_audit
              (company_id, escalation_request_id, saved_escalation_id,
               event, actor, endpoint_id, operation, detail, prev_hash, row_hash, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                str(company_id) if company_id else None,
                str(escalation_request_id) if escalation_request_id else None,
                str(saved_escalation_id) if saved_escalation_id else None,
                event,
                actor,
                str(endpoint_id) if endpoint_id else None,
                operation,
                json.dumps(detail),
                prev_hash,
                row_hash,
                ts,
            ),
        )
    conn.commit()
