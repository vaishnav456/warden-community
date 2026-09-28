"""Encrypt existing tenant endpoint data in place.

Run after the additive schema migration and compatible server code are live:
    python tools/encrypt_endpoint_private_data.py

The migration is restartable. It prints identifiers and counts only, never
plaintext or keys. BYOK tenants must be unlocked in the same process first.
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
if str(SERVER) not in sys.path:
    sys.path.insert(0, str(SERVER))

import db


def _encrypted(value):
    return isinstance(value, str) and value.startswith("v2:")


def endpoint_patch(company, row):
    patch = {}
    for field in db._ENDPOINT_TEXT_FIELDS:
        value = row.get(field)
        if value is None:
            continue
        plaintext = db._endpoint_decrypt(company, field, value)
        if not _encrypted(value):
            patch[field] = db._endpoint_encrypt(company, field, plaintext)
        if field == "hardware_id":
            patch["hardware_id_hash"] = db.blind_index(
                company, plaintext, "endpoint.hardware-id",
            )
        elif field == "installation_id":
            patch["installation_id_hash"] = db.blind_index(
                company, plaintext, "endpoint.installation-id",
            )

    for field, encrypted_column in db._ENDPOINT_JSON_FIELDS.items():
        encrypted = row.get(encrypted_column)
        if not _encrypted(encrypted):
            legacy = row.get(field)
            if legacy is None:
                legacy = [] if field == "tags" else {}
            patch[encrypted_column] = db._endpoint_encrypt(company, field, legacy)
        patch[field] = [] if field == "tags" else {}

    patch["private_data_encryption_version"] = 1
    return patch


def migrate_company(company, dry_run=False):
    company_id = company["id"]
    counts = {"endpoints": 0, "events": 0, "alerts": 0, "audit": 0}
    endpoints = db._get(
        f"endpoints?company_id=eq.{db._q(company_id)}&order=created_at.asc"
    )
    endpoint_ids = set()
    for row in endpoints:
        endpoint_ids.add(str(row["id"]))
        patch = endpoint_patch(company, row)
        if not dry_run:
            db._patch(f"endpoints?id=eq.{db._q(row['id'])}", patch)
        counts["endpoints"] += 1

    for endpoint_id in endpoint_ids:
        events = db._get(
            f"endpoint_events?endpoint_id=eq.{db._q(endpoint_id)}"
            "&detail_encrypted=is.null&order=created_at.asc"
        )
        for row in events:
            patch = {
                "detail": {},
                "detail_encrypted": db._endpoint_encrypt(
                    company, "event.detail", row.get("detail") or {},
                ),
            }
            if not dry_run:
                db._patch(f"endpoint_events?id=eq.{db._q(row['id'])}", patch)
            counts["events"] += 1

    alerts = db._get(
        f"alerts?company_id=eq.{db._q(company_id)}&order=created_at.asc"
    )
    for row in alerts:
        patch = {}
        for field in ("title", "message", "resolution_note"):
            value = row.get(field)
            if value is not None and not _encrypted(value):
                patch[field] = db._endpoint_encrypt(
                    company, f"alert.{field}", value,
                )
        if not _encrypted(row.get("detail_encrypted")):
            patch.update({
                "detail": {},
                "detail_encrypted": db._endpoint_encrypt(
                    company, "alert.detail", row.get("detail") or {},
                ),
            })
        if patch and not dry_run:
            db._patch(f"alerts?id=eq.{db._q(row['id'])}", patch)
        counts["alerts"] += 1

    # audit_log is append-only to the application role. The schema migration
    # installs a narrowly-scoped temporary RPC for this conversion; the
    # finalize migration removes it after the audit chain is rebuilt.
    audits = db._get(
        f"audit_log?company_id=eq.{db._q(company_id)}"
        "&detail_encrypted=is.null&order=created_at.asc"
    )
    for row in audits:
        encrypted = db._endpoint_encrypt(
            company, "audit.detail", row.get("detail") or {},
        )
        if not dry_run:
            db._rpc("migrate_audit_detail_encryption", {
                "p_audit_id": row["id"],
                "p_company_id": company_id,
                "p_detail_encrypted": encrypted,
            })
        counts["audit"] += 1
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--company-id")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    companies = db._get("companies?is_active=eq.true&order=created_at.asc")
    if args.company_id:
        companies = [
            row for row in companies if str(row["id"]) == str(args.company_id)
        ]
    totals = {"endpoints": 0, "events": 0, "alerts": 0, "audit": 0}
    for company in companies:
        if not company.get("wrapped_dek"):
            raise RuntimeError(
                f"Tenant {company['id']} has no encryption key; refusing plaintext migration"
            )
        result = migrate_company(company, dry_run=args.dry_run)
        for key, value in result.items():
            totals[key] += value
        print(f"tenant={company['id']} counts={result}")
    print(f"complete dry_run={args.dry_run} totals={totals}")


if __name__ == "__main__":
    main()
