"""Restartable heartbeat-metric encryption backfill; dry run by default."""
import argparse
import pathlib
import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
import config
import db


def backfill(apply=False):
    if apply and not config.ENCRYPT_HEARTBEAT_TELEMETRY:
        raise RuntimeError("Enable encrypted telemetry writes before backfilling")
    counts = dict(endpoints=0, metrics=0, skipped=0)
    companies = {}
    cursor = ""
    while True:
        path = "endpoints?heartbeat_encrypted=is.null&order=id.asc&limit=200"
        if cursor:
            path += "&id=gt." + db._q(cursor)
        rows = db._get(path) or []
        if not rows:
            break
        for row in rows:
            cursor = str(row["id"])
            company_id = row["company_id"]
            company = companies.setdefault(company_id, None)
            if company is None:
                company = companies[company_id] = db.get_company_by_id(company_id)
            try:
                metrics = {key: row[key] for key in db._HEARTBEAT_METRIC_FIELDS if row.get(key) is not None}
                encrypted = db._endpoint_encrypt(company, "heartbeat", metrics)
            except Exception:
                counts["skipped"] += 1
                continue
            if apply:
                # Do not overwrite a concurrent newer encrypted heartbeat.
                query = f"endpoints?id=eq.{db._q(cursor)}&heartbeat_encrypted=is.null"
                last_seen = row.get("last_seen")
                query += "&last_seen=" + ("eq." + db._q(last_seen) if last_seen else "is.null")
                db._patch(query, dict(heartbeat_encrypted=encrypted,
                                      **{key: None for key in db._HEARTBEAT_METRIC_FIELDS}))
            counts["endpoints"] += 1
    cursor = ""
    while True:
        path = "endpoint_metrics?metrics_encrypted=is.null&order=id.asc&limit=200"
        if cursor:
            path += "&id=gt." + db._q(cursor)
        rows = db._get(path) or []
        if not rows:
            break
        for row in rows:
            cursor = str(row["id"])
            try:
                company = db._endpoint_company(row["endpoint_id"])
                metrics = {key: row[key] for key in ("cpu_pct", "ram_used_pct") if key in row}
                encrypted = db._endpoint_encrypt(company, "metric", metrics)
            except Exception:
                counts["skipped"] += 1
                continue
            if apply:
                db._patch(f"endpoint_metrics?id=eq.{db._q(cursor)}&metrics_encrypted=is.null",
                          dict(metrics_encrypted=encrypted, cpu_pct=None, ram_used_pct=None))
            counts["metrics"] += 1
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print("Heartbeat backfill", "applied" if args.apply else "dry-run", backfill(args.apply))
