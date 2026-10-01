"""Bounded read-only CSV exports. Never export job payloads, grants or keys."""
import csv
import io
import json
from datetime import datetime, timezone, timedelta
import db

KINDS = {
 'audit': ('audit_log','created_at',['id','created_at','action','actor_id','endpoint_id','branch_id']),
 'storage': ('audit_log','created_at',['id','created_at','action','actor_id','endpoint_id','branch_id']),
 'remote': ('remote_sessions','started_at',['id','started_at','ended_at','endpoint_id','admin_id','status','consent_required','consent_status','access_mode','fail_reason']),
 'jobs': ('jobs','created_at',['id','created_at','completed_at','endpoint_id','branch_id','type','status','exit_code']),
}


def csv_cell(value):
    text = json.dumps(value,separators=(',',':'),default=str) if isinstance(value,(dict,list)) else str(value if value is not None else '')
    # Spreadsheet formula injection also applies to CSVs generated internally.
    if text.lstrip().startswith(('=','+','-','@')) or text.startswith(('\t','\r','\n')):
        text = "'"+text
    return text


def export(company_id,kind,branch_id=None,days=30):
    if kind not in KINDS or not 1 <= days <= 90:
        raise ValueError('Choose a supported report and 1–90 days')
    table,date,columns = KINDS[kind]
    cutoff = (datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
    path = f"{table}?company_id=eq.{db._q(company_id)}&{date}=gte.{db._q(cutoff)}&order={date}.desc,id.desc"
    if kind == 'storage':
        path += '&or=(action.ilike.*storage*,action.ilike.*package*,action.ilike.*app_*,action.ilike.*home*)'
    allowed = {str(ep['id']) for ep in db.get_endpoints(company_id,branch_id=branch_id)} if branch_id else None
    out=io.StringIO(newline='')
    writer=csv.writer(out);writer.writerow(columns)
    scanned=0
    # Bounded export is explicit; no misleading silently truncated downloads.
    while True:
        page=db._get(path+f'&limit=1000&offset={scanned}&select='+','.join(columns))
        scanned+=len(page)
        if scanned > 10000:
            raise ValueError('Report exceeds 10,000 rows; select a shorter date range')
        for row in page:
            if allowed is not None and str(row.get('endpoint_id')) not in allowed:
                continue
            writer.writerow([csv_cell(row.get(column)) for column in columns])
        if len(page)<1000:
            return out.getvalue()
