"""Small-business workflows; no device action happens on a GET request."""
from datetime import datetime,timezone
from flask import Blueprint,abort,g,render_template,request,redirect,url_for,flash,jsonify,Response
import db
from middleware.auth import login_required,company_required,role_required,require_branch_scope
from services import fleet_tools as tools
from services.entitlements import check_job
from services.device_health import age_seconds
from services import support_workflow
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
    from services import helpdesk
    endpoints={str(ep['id']):ep for ep in scoped_endpoints()}
    rows=db._get(f"support_requests?company_id=eq.{db._q(g.company['id'])}&order=updated_at.desc&limit=500")
    scoped=[helpdesk.hydrate(row,g.company,endpoints[str(row['endpoint_id'])])
            for row in rows if str(row['endpoint_id']) in endpoints]
    query=request.args.get('q','').strip().casefold()[:160]
    state=request.args.get('state','active')
    if state not in {'active','all','open','claimed','resolved','mine'}:state='active'
    counts={key:sum(row['status']==key for row in scoped) for key in ('open','claimed','resolved')}
    def matches(row):
        if state=='active' and row['status']=='resolved':return False
        if state in counts and row['status']!=state:return False
        if state=='mine' and str(row.get('claimed_by'))!=str(g.admin['id']):return False
        haystack=' '.join(str(value or '') for value in (row['number'],row['request'].get('subject'),
            row['request'].get('username'),row['endpoint'].get('display_name'),row['endpoint'].get('hostname')))
        return not query or query in haystack.casefold()
    return render_template('fleet/support.html',requests=[row for row in scoped if matches(row)],
        counts=counts,query=request.args.get('q','')[:160],state=state,active_page='fleet_support')


def support_ticket(request_id):
    from services import helpdesk
    try:request_id=helpdesk.identifier(request_id)
    except ValueError:abort(404)
    rows=db._get(f"support_requests?id=eq.{db._q(request_id)}&company_id=eq.{db._q(g.company['id'])}")
    if not rows:abort(404)
    endpoint=next((ep for ep in scoped_endpoints() if str(ep['id'])==str(rows[0]['endpoint_id'])),None)
    if not endpoint:abort(404)
    return rows[0],endpoint


@bp.get('/operations/support/new')
@login_required
@company_required
@role_required('superadmin','company_admin','branch_admin','technician')
def support_new():
    import uuid
    from services import helpdesk
    return render_template('fleet/support_new.html',endpoints=scoped_endpoints(),
        definition=helpdesk.load_form(g.company),ticket_id=str(uuid.uuid4()),active_page='fleet_support')


@bp.post('/operations/support/new')
@login_required
@company_required
@role_required('superadmin','company_admin','branch_admin','technician')
def support_create():
    from services import helpdesk
    endpoint=next((ep for ep in scoped_endpoints() if str(ep['id'])==request.form.get('endpoint_id')),None)
    if not endpoint:abort(404)
    definition=helpdesk.load_form(g.company)
    try:
        username=helpdesk.short(request.form.get('username'),256)
        body=helpdesk.ticket_content(dict(message=request.form.get('message'),subject=request.form.get('subject'),
            category=request.form.get('category'),priority=request.form.get('priority'),
            fields={field['id']:request.form.get('field_'+field['id'],'') for field in definition['fields']}),definition,username,endpoint.get('branch_id'))
        result=helpdesk.action(g.company,endpoint,request.form.get('ticket_id'),'create',
            admin=g.admin,username=username,body=body)
    except ValueError as exc:abort(400,str(exc))
    helpdesk.http_error(result)
    db.audit(g.company['id'],g.admin['id'],'support_requested',dict(request_id=result['id']),
        endpoint_id=endpoint['id'],branch_id=endpoint.get('branch_id'))
    return redirect(url_for('fleet_tools.support_detail',request_id=result['id']),303)


@bp.get('/operations/support/form')
@login_required
@company_required
@role_required('superadmin','company_admin')
def support_form():
    import json
    from services import helpdesk
    return render_template('fleet/support_form.html',definition=helpdesk.load_form(g.company),branches=db.get_branches(g.company['id']),
                           active_page='fleet_support')


@bp.post('/operations/support/form')
@login_required
@company_required
@role_required('superadmin','company_admin')
def support_form_save():
    import json
    from services import helpdesk
    raw=request.form.get('definition')
    if raw and len(raw)>12000:abort(400)
    try:
        if raw:
            candidate=json.loads(raw)
        else:
            columns=[request.form.getlist(key) for key in ('field_id','field_label','field_type','field_options','field_condition')]
            if len(columns[0])>8 or len({len(column) for column in columns})!=1:raise ValueError('Invalid question list.')
            required=set(request.form.getlist('field_required'))
            candidate=dict(categories=[value.strip() for value in request.form.get('categories','').splitlines() if value.strip()],
                fields=[dict(id=key,label=label,type=kind,required=key in required,
                    **(dict(options=[value.strip() for value in options.splitlines() if value.strip()]) if kind=='select' else {}),
                    **(dict(show_if=json.loads(condition)) if condition and condition!='null' else {}))
                    for key,label,kind,options,condition in zip(*columns)])
        definition=helpdesk.form_definition(candidate)
        branch_ids={str(branch['id']) for branch in db.get_branches(g.company['id'])}
        if any(rule['source']=='branch' and rule['value'] not in branch_ids
               for field in definition['fields'] for rule in field.get('show_if',{}).get('rules',[])):
            raise ValueError('Choose a branch from this organization.')
    except (ValueError,TypeError) as exc:abort(400,str(exc))
    db._post('support_forms?on_conflict=company_id',dict(company_id=g.company['id'],
        definition_encrypted=db.encrypt_field(g.company,definition,'support.form'),updated_at=db._now_iso()),
        prefer='resolution=merge-duplicates,return=representation')
    db.audit(g.company['id'],g.admin['id'],'support_form_updated',dict(custom_fields=len(definition['fields'])))
    flash('Helpdesk form saved. Existing tickets retain their original field labels and values.','success')
    return redirect(url_for('fleet_tools.support_form'),303)


@bp.get('/operations/support/<request_id>')
@login_required
@company_required
def support_detail(request_id):
    import uuid
    from services import helpdesk
    row,endpoint=support_ticket(request_id)
    admins=[a for a in db.get_admins_for_company(g.company['id']) if a.get('is_active')
            and a.get('role') in {'company_admin','branch_admin','technician'}
            and (a.get('role')!='branch_admin' or str(a.get('branch_id'))==str(endpoint.get('branch_id')))]
    try:page=max(0,min(10000,int(request.args.get('message_page',0))))
    except (ValueError,TypeError):abort(400)
    return render_template('fleet/support_detail.html',item=helpdesk.hydrate(row,g.company,endpoint,True,page),
        admins=admins,message_id=str(uuid.uuid4()),active_page='fleet_support')


@bp.post('/operations/support/<request_id>/<action>')
@login_required
@company_required
@role_required('superadmin','company_admin','branch_admin','technician')
def support_action(request_id,action):
    import uuid
    from services import helpdesk
    if action not in {'claim','resolve','reply','reopen','assign','queued','remote','onsite','waiting_user'}:abort(400)
    row,endpoint=support_ticket(request_id)
    owner=row.get('claimed_by')
    if owner and str(owner)!=str(g.admin['id']) and g.admin['role'] in {'branch_admin','technician'}:abort(403)
    if row['status']=='resolved' and action!='reopen':abort(409,'Reopen the ticket before replying.')
    try:
        if action=='reply':
            body=dict(author=g.admin.get('full_name') or 'IT support',kind='reply',
                      message=support_workflow.text(request.form.get('message')))
        else:
            body=dict(author=g.admin.get('full_name') or 'IT support',kind='event',
                      message={'claim':'IT support claimed this ticket.','resolve':'Ticket marked resolved.',
                      'reopen':'Ticket reopened.','assign':'Ticket assigned to IT support.','queued':'Support is queued.',
                      'remote':'Remote support arranged; normal user consent still applies.',
                      'onsite':'On-site visit arranged.','waiting_user':'Waiting for information from you.'}[action])
        visit=support_workflow.visit_time(request.form.get('visit_at')) if action=='onsite' else None
        if visit:body['message']+=' Visit: '+visit
        result=helpdesk.action(g.company,endpoint,request_id,action,admin=g.admin,body=body,
            message_id=request.form.get('message_id') or str(uuid.uuid4()) if action=='reply' else None,
            assignee=request.form.get('assignee') if action=='assign' else None,visit=visit)
    except ValueError as exc:abort(400,str(exc))
    helpdesk.http_error(result)
    db.audit(g.company['id'],g.admin['id'],'support_request_'+action,dict(request_id=request_id),
        endpoint_id=endpoint['id'],branch_id=endpoint.get('branch_id'))
    return redirect(url_for('fleet_tools.support_detail',request_id=request_id),303)


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
