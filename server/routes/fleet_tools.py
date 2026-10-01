"""Small-business workflows; no device action happens on a GET request."""
from datetime import datetime,timezone
from flask import Blueprint,abort,g,render_template,request,redirect,url_for,flash,jsonify,Response
import db
from middleware.auth import login_required,company_required,role_required,require_branch_scope
from services import fleet_tools as tools
from services.entitlements import check_job
from services.device_health import age_seconds
from policy_settings import validate_settings_dict

bp=Blueprint('fleet_tools',__name__)


def scoped_endpoints():
    branch=g.admin.get('branch_id') if g.admin.get('role')=='branch_admin' else None
    if g.admin.get('role')=='branch_admin' and not branch:abort(403)
    return db.get_endpoints(g.company['id'],branch_id=branch)


def branch_value(value):
    if not value:return None
    branch=db.get_branch(value)
    if not branch or str(branch.get('company_id'))!=str(g.company['id']):abort(404)
    require_branch_scope(value)
    return value


@bp.get('/operations/software')
@login_required
@company_required
def software():
    rules=tools.rules(g.company['id'])
    endpoints=scoped_endpoints()
    if g.admin.get('role')=='branch_admin':
        rules=[r for r in rules if r.get('branch_id') is None or str(r['branch_id'])==str(g.admin.get('branch_id'))]
    rows=[]
    receipts=[]
    endpoint_map={str(ep['id']):ep for ep in endpoints}
    for rule in rules:
        for receipt in db._get(f"software_patch_receipts?rule_id=eq.{db._q(rule['id'])}&order=created_at.desc&limit=100"):
            endpoint=endpoint_map.get(str(receipt.get('endpoint_id')))
            if not endpoint:continue
            jobs=db._get(f"jobs?id=eq.{db._q(receipt.get('job_id'))}&company_id=eq.{db._q(g.company['id'])}&endpoint_id=eq.{db._q(endpoint['id'])}&select=id,status,exit_code,completed_at") if receipt.get('job_id') else []
            receipts.append(dict(endpoint=endpoint,rule=rule,receipt=receipt,job=jobs[0] if jobs else {}))
    for endpoint in endpoints:
        inventory=tools.inventory(endpoint['id'])
        for rule in rules:
            found=tools.match_patch(rule,endpoint,inventory)
            if found:rows.append(dict(endpoint=endpoint,rule=rule,found=found))
    return render_template('fleet/software.html',rules=rules,rows=rows,receipts=receipts,
        packages=db.get_app_library(g.company['id']),branches=db.get_branches(g.company['id']),active_page='fleet_software')


@bp.post('/operations/software/rules')
@login_required
@company_required
@role_required('superadmin','company_admin')
def create_software_rule():
    if request.form.get('confirmation')!='APPROVE':abort(400,'Type APPROVE to authorize the selected package')
    if not check_job(g.company['id'],'INSTALL_APP').allowed:abort(403)
    app=db.get_app(request.form.get('app_id'))
    if not app or (app.get('company_id') and str(app['company_id'])!=str(g.company['id'])):abort(404)
    version=request.form.get('target_version','').strip()
    name=request.form.get('inventory_name','').strip()
    publisher=request.form.get('publisher','').strip()
    if not tools.numeric_version(version) or not 1<=len(name)<=160 or not 1<=len(publisher)<=160 or len(version)>80:abort(400)
    try:start,end=int(request.form.get('window_start',0)),int(request.form.get('window_end',0))
    except ValueError:abort(400)
    if not 0<=start<=23 or not 0<=end<=23:abort(400)
    from services.package_storage import installation
    with installation(g.company['id'],dict(app_id=app['id'])):
        rule=db._post('software_patch_rules',dict(company_id=g.company['id'],branch_id=branch_value(request.form.get('branch_id')),
          app_id=app['id'],inventory_name=name,publisher=publisher,target_version=version,package_sha256=app['sha256'],
          install_args=app.get('install_args') or '',approved_by=g.admin['id'],enabled=request.form.get('enabled')=='1',window_start=start,window_end=end))[0]
    db.audit(g.company['id'],g.admin['id'],'software_patch_rule_approved',dict(rule_id=rule['id'],app_id=app['id'],enabled=rule['enabled']),branch_id=rule.get('branch_id'))
    flash('Approved rule saved. Only uniquely matched, older numeric versions from fresh inventory are eligible.','success')
    return redirect(url_for('fleet_tools.software'),303)


@bp.post('/operations/software/rules/<rule_id>/<action>')
@login_required
@company_required
@role_required('superadmin','company_admin')
def control_software_rule(rule_id,action):
    if action not in {'disable','delete'}:abort(400)
    path=f"software_patch_rules?id=eq.{db._q(rule_id)}&company_id=eq.{db._q(g.company['id'])}"
    if not db._get(path):abort(404)
    db._patch(path,dict(enabled=False))
    if action=='delete':db._delete(path)
    db.audit(g.company['id'],g.admin['id'],'software_patch_rule_'+action,dict(rule_id=rule_id))
    return redirect(url_for('fleet_tools.software'),303)


@bp.get('/operations/support')
@login_required
@company_required
def support():
    endpoints={str(ep['id']):ep for ep in scoped_endpoints()}
    rows=db._get(f"support_requests?company_id=eq.{db._q(g.company['id'])}&order=created_at.desc&limit=500")
    scoped=[]
    for row in rows:
        endpoint=endpoints.get(str(row['endpoint_id']))
        if endpoint:
            row['request']=db.decrypt_field(g.company,row.pop('request_encrypted',None),'support.request') or {}
            row['endpoint']=endpoint;scoped.append(row)
    return render_template('fleet/support.html',requests=scoped,active_page='fleet_support')


@bp.post('/operations/support/<request_id>/<action>')
@login_required
@company_required
@role_required('superadmin','company_admin','branch_admin')
def support_action(request_id,action):
    if action not in {'claim','resolve'}:abort(400)
    path=f"support_requests?id=eq.{db._q(request_id)}&company_id=eq.{db._q(g.company['id'])}"
    rows=db._get(path)
    if not rows:abort(404)
    endpoint=next((ep for ep in scoped_endpoints() if str(ep['id'])==str(rows[0]['endpoint_id'])),None)
    if not endpoint:abort(404)
    if action=='claim':
        result=db._patch(path+'&status=eq.open',dict(status='claimed',claimed_by=g.admin['id']))
    else:
        if rows[0].get('claimed_by') and str(rows[0]['claimed_by'])!=str(g.admin['id']) and g.admin['role']=='branch_admin':abort(403)
        result=db._patch(path+'&status=in.(open,claimed)',dict(status='resolved',resolved_at=db._now_iso()))
    if not result:abort(409,'Request was already changed; refresh')
    db.audit(g.company['id'],g.admin['id'],'support_request_'+action,dict(request_id=request_id),endpoint_id=endpoint['id'],branch_id=endpoint.get('branch_id'))
    return redirect(url_for('fleet_tools.support'),303)


@bp.get('/operations/traffic')
@login_required
@company_required
@role_required('superadmin','company_admin')
def traffic():
    return render_template('fleet/traffic.html',rules=db._get(f"branch_traffic_rules?company_id=eq.{db._q(g.company['id'])}"),
      branches=db.get_branches(g.company['id']),nodes=db.get_home_nodes(g.company['id']),active_page='fleet_traffic')


@bp.post('/operations/traffic')
@login_required
@company_required
@role_required('superadmin','company_admin')
def save_traffic():
    branch=branch_value(request.form.get('branch_id'))
    if not branch:abort(400)
    try:values={key:int(request.form.get(key,'')) for key in ('business_start','business_end','business_kbps','offhours_kbps')}
    except ValueError:abort(400)
    if any(not 0<=values[key]<=23 for key in ('business_start','business_end')) or any(not 16<=values[key]<=1048576 for key in ('business_kbps','offhours_kbps')):abort(400)
    node_id=request.form.get('package_cache_node_id') or None
    if node_id:
        node=next((n for n in db.get_home_nodes(g.company['id']) if str(n['id'])==str(node_id)),None)
        if not node or (node.get('branch_id') and str(node['branch_id'])!=str(branch)):abort(404)
        if node.get('deployment_mode')=='p2p':abort(400,'Package caching currently requires a LAN or public HTTPS node')
        if not (node.get('capabilities') or {}).get('package_cache'):abort(409,'Update the Home Node before selecting it as a package cache')
    values.update(company_id=g.company['id'],branch_id=branch,defer_updates=request.form.get('defer_updates')=='1',package_cache_node_id=node_id,updated_at=db._now_iso())
    db._post('branch_traffic_rules?on_conflict=company_id,branch_id',values,prefer='resolution=merge-duplicates,return=representation')
    db.audit(g.company['id'],g.admin['id'],'branch_traffic_configured',{k:v for k,v in values.items() if k!='company_id'},branch_id=branch)
    flash('Traffic policy saved. New grants/downloads pick it up; limits are per device, not an aggregate branch guarantee.','success')
    return redirect(url_for('fleet_tools.traffic'),303)


@bp.post('/operations/traffic/<branch_id>/remove')
@login_required
@company_required
@role_required('superadmin','company_admin')
def remove_traffic(branch_id):
    branch_value(branch_id)
    db._delete(f"branch_traffic_rules?company_id=eq.{db._q(g.company['id'])}&branch_id=eq.{db._q(branch_id)}")
    db.audit(g.company['id'],g.admin['id'],'branch_traffic_removed',{},branch_id=branch_id)
    return redirect(url_for('fleet_tools.traffic'),303)


@bp.get('/operations/connections')
@login_required
@company_required
def connections():
    endpoints={str(ep['id']):ep for ep in scoped_endpoints()}
    sessions=db._get(f"remote_sessions?company_id=eq.{db._q(g.company['id'])}&order=started_at.desc&limit=100")
    sessions=[dict(row,endpoint=endpoints[str(row['endpoint_id'])]) for row in sessions if str(row.get('endpoint_id')) in endpoints]
    jobs=db.get_home_sync_jobs(g.company['id'],branch_id=g.admin.get('branch_id') if g.admin.get('role')=='branch_admin' else None,limit=30)
    from routes.home import _home_transfer_view
    transfers=[_home_transfer_view(job,endpoints) for job in jobs if str(job.get('endpoint_id')) in endpoints]
    return render_template('fleet/connections.html',sessions=sessions,transfers=transfers,active_page='fleet_connections')


@bp.get('/operations/recovery')
@login_required
@company_required
@role_required('superadmin','company_admin')
def recovery():
    nodes=db.get_home_nodes(g.company['id'])
    for node in nodes:
        caps=node.get('capabilities') or {}
        node['backup']=caps.get('independent_backup') if isinstance(caps.get('independent_backup'),dict) else {}
        node['report_age']=age_seconds(node.get('last_seen'))
        node['key_reported']=bool(caps.get('encryption_key_id'))
    return render_template('fleet/recovery.html',nodes=nodes,spaces=db.get_home_spaces(g.company['id']),active_page='fleet_recovery')


@bp.get('/operations/reports')
@login_required
@company_required
def reports():
    return render_template('fleet/reports.html',active_page='fleet_reports')


@bp.get('/operations/reports/<kind>.csv')
@login_required
@company_required
def report_export(kind):
    from services.fleet_reports import export
    # Resolve scope even for an empty export.
    scoped_endpoints()
    try:
        days=int(request.args.get('days',30))
        data=export(g.company['id'],kind,g.admin.get('branch_id') if g.admin.get('role')=='branch_admin' else None,days)
    except (ValueError,TypeError) as exc:abort(400,str(exc))
    return Response(data,mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename="warden-{kind}.csv"','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


PRESETS={
 'baseline':('Small-business baseline',dict(firewall_all_profiles_enabled=True,screen_lock_timeout_minutes=10,guest_account_enabled=False,rdp_network_level_auth_required=True)),
 'restricted_usb':('Restricted removable storage',dict(usb_storage_enabled=False,autorun_enabled=False)),
 'branch_usb_exception':('Branch USB exception',dict(usb_storage_enabled=True,autorun_enabled=False)),
}


@bp.get('/operations/device-policies')
@login_required
@company_required
def device_policies():
    scoped_endpoints()
    return render_template('fleet/policies.html',presets=PRESETS,active_page='fleet_policies')


@bp.post('/operations/device-policies/<preset>')
@login_required
@company_required
@role_required('superadmin','company_admin')
def create_preset(preset):
    if preset not in PRESETS:abort(400)
    name,settings=PRESETS[preset]
    validate_settings_dict(settings)
    template=db.create_policy_template(g.company['id'],name,'Review and assign before deployment. Creating this template does not change a device.',settings,g.admin['id'])
    db.audit(g.company['id'],g.admin['id'],'device_policy_preset_created',dict(template_id=template['id'],preset=preset))
    flash('Template created. Assign it to a branch or device, review the effective settings, then deploy explicitly.','success')
    return redirect(url_for('security_management.effective_policy'),303)
