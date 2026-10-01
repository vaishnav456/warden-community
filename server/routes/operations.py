"""Tenant/branch-scoped device health; remediation uses existing approval paths."""
from flask import Blueprint, abort, g, render_template, request, redirect, url_for, flash
import db
from middleware.auth import login_required, company_required, role_required
from services.device_health import findings

bp = Blueprint('operations', __name__)


@bp.get('/operations/storage')
@login_required
@company_required
@role_required('superadmin','company_admin')
def storage():
    from services.storage_cleanup import inventory, pressure
    from services.tenant_storage import usage
    used = usage(g.company['id'])
    limit = 0  # Community has no commercial capacity gate.
    packages = [app for app in db.get_app_library(g.company['id'],include_global=False,include_deleting=True) if str(app.get('company_id'))==str(g.company['id'])]
    return render_template('operations/storage.html',storage=used,limit=limit,
                           pressure=pressure(used['used_bytes'],limit),packages=packages,
                           installers=inventory(g.company['id']),active_page='storage_cleanup')


@bp.post('/operations/storage/installers/<build_id>/delete')
@login_required
@company_required
@role_required('superadmin','company_admin')
def delete_installer(build_id):
    if request.form.get('confirmation') != 'DELETE':
        abort(400,'Type DELETE to confirm')
    from services.storage_cleanup import remove_msi
    try:
        freed = remove_msi(g.company['id'],build_id)
    except (ValueError,OSError) as exc:
        flash(str(exc),'error')
    else:
        db.audit(g.company['id'],g.admin['id'],'obsolete_installer_deleted',{'build_id':build_id,'freed_bytes':freed})
        flash(f'Installer removed; {freed} bytes freed. Existing installations and update archives are unchanged.','success')
    return redirect(url_for('operations.storage'),code=303)


@bp.get('/operations/updates')
@login_required
@company_required
@role_required('superadmin','company_admin')
def updates():
    from services.agent_rollouts import campaigns
    return render_template('operations/updates.html', rollouts=campaigns(g.company['id']),
                           endpoints=db.get_endpoints(g.company['id']),
                           builds=[b for b in db.get_build_requests(g.company['id'],100) if b.get('status')=='completed' and not b.get('deletion_requested_at')], active_page='updates')


@bp.post('/operations/updates')
@login_required
@company_required
@role_required('superadmin','company_admin')
def create_rollout():
    from services.agent_rollouts import create
    from services.agent_updates import AgentBuildUnavailable
    from services.entitlements import check_job
    decision = check_job(g.company['id'],'UPDATE_AGENT')
    if not decision.allowed:
        abort(403)
    try:
        row = create(g.company['id'],request.form.get('build_id'),request.form.getlist('endpoint_id'),g.admin['id'],
                     int(request.form.get('canary',1)),int(request.form.get('batch',5)),
                     int(request.form.get('window_start',0)),int(request.form.get('window_end',0)),
                     canary_ids=request.form.getlist('canary_endpoint_id'))
    except (ValueError,TypeError,AgentBuildUnavailable) as exc:
        flash(str(exc),'error')
        return redirect(url_for('operations.updates'),code=303)
    except (RuntimeError,OSError):
        flash('Rollout was not created. Refresh to check conflicting campaigns, then retry when database access is available.','error')
        return redirect(url_for('operations.updates'),code=303)
    db.audit(g.company['id'],g.admin['id'],'agent_rollout_created',{'rollout_id':row['id'],'build_id':row['build_id']})
    return redirect(url_for('operations.updates'),code=303)


@bp.post('/operations/updates/<rollout_id>/<action>')
@login_required
@company_required
@role_required('superadmin','company_admin')
def control_rollout(rollout_id,action):
    import uuid
    rows = db._get(f"agent_rollouts?id=eq.{db._q(rollout_id)}&company_id=eq.{db._q(g.company['id'])}")
    if not rows:
        abort(404)
    if action not in {'pause','resume','cancel','rollback'}:
        abort(400)
    if action in {'resume','rollback'}:
        from services.entitlements import check_job
        if not check_job(g.company['id'],'UPDATE_AGENT').allowed:
            abort(403)
    token = str(uuid.uuid4())
    if not db._rpc('claim_agent_rollout',{'p_id':rollout_id,'p_token':token}):
        abort(409,'Rollout is busy; retry shortly')
    try:
        row = db._get(f"agent_rollouts?id=eq.{db._q(rollout_id)}")[0]
        if action == 'rollback' and request.form.get('confirmation') != 'ROLLBACK':
            abort(400,'Type ROLLBACK to authorize returning affected devices to their previous build')
        if row['status'] in {'cancelled','completed'} and action != 'rollback':
            abort(409)
        status = {'pause':'paused','resume':'expanding','cancel':'cancelled','rollback':'rolling_back'}[action]
        if action == 'resume' and any(t['state']=='failed' for t in row['targets'].values()):
            abort(409,'Resolve failed devices or rollback before resuming')
        if action=='resume' and any(t['state'] in {'rolled_back','rollback_queued'} for t in row['targets'].values()):
            abort(409,'Cancel the rollback campaign before starting a new release')
        if action == 'resume' and sum(t['state']=='verified' for t in row['targets'].values())<row['canary_count']:
            status = 'canary'
        db._patch(f"agent_rollouts?id=eq.{db._q(rollout_id)}&lease_token=eq.{token}",dict(status=status,pause_reason=None))
        db.audit(g.company['id'],g.admin['id'],'agent_rollout_'+action,{'rollout_id':rollout_id})
    finally:
        db._patch(f"agent_rollouts?id=eq.{db._q(rollout_id)}&lease_token=eq.{token}",dict(lease_token=None,lease_until=None))
    flash('Rollout updated. Already dispatched jobs are not cancelled.','success')
    return redirect(url_for('operations.updates'),code=303)


@bp.get('/operations/health')
@login_required
@company_required
def health():
    branch = g.admin.get('branch_id') if g.admin.get('role') == 'branch_admin' else None
    if g.admin.get('role') == 'branch_admin' and not branch:
        abort(403)
    builds = {}
    rows = []
    for endpoint in db.get_endpoints(g.company['id'], branch_id=branch):
        platform = db.endpoint_target_platform(endpoint)
        if platform not in builds:
            builds[platform] = db.get_latest_completed_build(platform) or {}
        rows.append({'endpoint': endpoint, 'findings': findings(endpoint, builds[platform].get('agent_version'))})
    rows.sort(key=lambda row: (-len(row['findings']), str(row['endpoint'].get('hostname') or '')))
    return render_template('operations/health.html', rows=rows, active_page='device_health')
