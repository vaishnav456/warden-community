import unittest
import copy
import hashlib
import pathlib
import tempfile
import zipfile
from contextlib import ExitStack
from unittest import mock
from datetime import datetime,timezone,timedelta
from urllib.parse import parse_qs,unquote
from services import agent_rollouts as rollouts
from services.device_health import findings,remote_diagnostic
from services.storage_cleanup import pressure


class ReliabilityTests(unittest.TestCase):
    def undecorated(self,function):
        while hasattr(function,'__wrapped__'):
            function=function.__wrapped__
        return function

    def test_sync_retry_rejects_another_tenants_job(self):
        from flask import Flask,g
        from werkzeug.exceptions import NotFound
        from routes import home
        app=Flask(__name__)
        with app.test_request_context('/storage/activity/job/retry',method='POST'):
            g.company=dict(id='tenant');g.admin=dict(role='company_admin')
            with mock.patch.object(home.db,'get_job',return_value=dict(company_id='other',type='SYNC_WARDEN_HOME')),mock.patch.object(home.db,'create_system_job_once') as create:
                with self.assertRaises(NotFound):self.undecorated(home.retry_sync)('job')
                create.assert_not_called()

    def test_history_request_rejects_device_in_another_tenant(self):
        from flask import Flask,g
        from werkzeug.exceptions import NotFound
        from routes import home
        app=Flask(__name__)
        with app.test_request_context('/storage/history',method='POST',data=dict(endpoint_id='foreign')):
            g.company=dict(id='tenant');g.admin=dict(role='company_admin')
            with mock.patch.object(home.db,'get_endpoint',return_value=dict(company_id='other')),mock.patch.object(home.db,'create_system_job_once') as create:
                with self.assertRaises(NotFound):self.undecorated(home.history)()
                create.assert_not_called()

    def test_progress_cannot_overwrite_completed_job(self):
        from flask import Flask,g
        from routes import agent_api
        app=Flask(__name__)
        report=dict(kind='warden_home_sync',version=1,status='running',uploaded=0,downloaded=0,unchanged=0,skipped=0,failed=0,uploaded_bytes=0,downloaded_bytes=0)
        with app.test_request_context('/api/agent/home-progress',method='POST',json=dict(job_id='job',report=report)):
            g.endpoint=dict(id='endpoint',company_id='tenant')
            with mock.patch.object(agent_api,'check_rate_limit',return_value=True),mock.patch.object(agent_api.db,'get_job',return_value=dict(endpoint_id='endpoint',type='SYNC_WARDEN_HOME')),mock.patch.object(agent_api.db,'get_company_by_id',return_value={}),mock.patch.object(agent_api.db,'encrypt_field',return_value='encrypted'),mock.patch.object(agent_api.db,'_patch',return_value=[]) as update:
                response=self.undecorated(agent_api.home_progress)()
                self.assertFalse(response.get_json()['accepted'])
                self.assertIn('status=eq.running',update.call_args.args[0])
                self.assertEqual(set(update.call_args.args[1]),{'log_output'})

    def test_progress_rejects_another_devices_job(self):
        from flask import Flask,g
        from routes import agent_api
        app=Flask(__name__)
        with app.test_request_context('/api/agent/home-progress',method='POST',json=dict(job_id='foreign',report={})):
            g.endpoint=dict(id='endpoint',company_id='tenant')
            with mock.patch.object(agent_api,'check_rate_limit',return_value=True),mock.patch.object(agent_api.db,'get_job',return_value=dict(endpoint_id='other',type='SYNC_WARDEN_HOME')),mock.patch.object(agent_api.db,'_patch') as update:
                _,status=self.undecorated(agent_api.home_progress)()
                self.assertEqual(status,404);update.assert_not_called()
    def test_pressure_boundaries(self):
        self.assertEqual([pressure(value,100) for value in [79,80,94,95,99,100]],[0,80,80,95,95,100])

    def test_maintenance_window_wraps_utc_midnight(self):
        now=datetime(2026,10,1,23,tzinfo=timezone.utc)
        self.assertTrue(rollouts.in_window(22,3,now))
        self.assertFalse(rollouts.in_window(2,10,now))
        self.assertTrue(rollouts.in_window(0,0,now))

    def test_health_handles_unknown_inventory_without_guessing(self):
        self.assertFalse(any(row['code']=='disk_health' for row in findings(dict(capability_details='invalid'))))
        self.assertFalse(any(row['code']=='security_service' for row in findings(dict(capability_details={'device_health':'invalid'}))))

    def test_remote_approval_cannot_be_bypassed_by_diagnostic(self):
        result=remote_diagnostic(dict(status='online'),dict(consent_required=True,consent_status='pending'))
        self.assertEqual(result['code'],'awaiting_approval')
        self.assertIn('not bypassed',result['action'])

    def test_timeout_does_not_assert_firewall_is_cause(self):
        result=remote_diagnostic(dict(status='online'),dict(fail_reason='Connection timed out'))
        self.assertIn('does not prove',result['action'])

    def campaign(self,state='queued'):
        return dict(id='rollout',company_id='company',build_id='build',status='canary',canary_count=1,batch_size=1,
                    window_start=0,window_end=0,lease_token='token',targets={'endpoint':dict(state=state,job_id='job',previous_version='1.0.0')})

    def advance(self,row,job,endpoint):
        with mock.patch.object(rollouts.db,'get_endpoints',return_value=[endpoint]),\
             mock.patch.object(rollouts.db,'get_build_request',return_value={}),\
             mock.patch.object(rollouts,'pinned_payload',return_value=dict(version='2.0.0')),\
             mock.patch.object(rollouts.db,'get_job',return_value=job),\
             mock.patch.object(rollouts.db,'get_active_remote_session',return_value=None),\
             mock.patch.object(rollouts.db,'has_inflight_job',return_value=False),\
             mock.patch.object(rollouts.db,'_patch'),mock.patch.object(rollouts.db,'_rpc') as dispatch:
            result=rollouts.advance(row,self.now)
            return result,dispatch.call_count

    def setUp(self):
        entitlement=mock.patch('services.entitlements.check_job',return_value=mock.Mock(allowed=True))
        entitlement.start();self.addCleanup(entitlement.stop)
        self.now=datetime(2026,10,1,12,tzinfo=timezone.utc)
        self.endpoint=dict(id='endpoint',status='online',agent_version='2.0.0',last_seen=(self.now-timedelta(seconds=1)).isoformat())

    def test_completed_job_requires_post_completion_heartbeat(self):
        endpoint=dict(self.endpoint,last_seen=(self.now-timedelta(seconds=60)).isoformat())
        result,count=self.advance(self.campaign(),dict(status='completed',completed_at=(self.now-timedelta(seconds=30)).isoformat()),endpoint)
        self.assertEqual(result['targets']['endpoint']['state'],'verifying')
        self.assertEqual(count,0)

    def test_expected_version_fresh_heartbeat_verifies_canary(self):
        result,count=self.advance(self.campaign(),dict(status='completed',completed_at=(self.now-timedelta(seconds=30)).isoformat()),self.endpoint)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(count,0)

    def test_failed_canary_pauses_without_dispatching(self):
        row=self.campaign();row['targets']['next']=dict(state='waiting')
        with mock.patch.object(rollouts.db,'get_endpoints',return_value=[self.endpoint,dict(id='next')]),\
             mock.patch.object(rollouts.db,'get_build_request',return_value={}),\
             mock.patch.object(rollouts,'pinned_payload',return_value=dict(version='2.0.0')),\
             mock.patch.object(rollouts.db,'get_job',return_value=dict(status='failed')),\
             mock.patch.object(rollouts.db,'_rpc') as dispatch:
            result=rollouts.advance(row,self.now)
        self.assertEqual(result['status'],'paused');dispatch.assert_not_called()

    def test_verification_timeout_pauses_campaign(self):
        endpoint=dict(self.endpoint,agent_version='1.0.0')
        result,count=self.advance(self.campaign(),dict(status='completed',completed_at=(self.now-timedelta(seconds=601)).isoformat()),endpoint)
        self.assertEqual(result['status'],'paused');self.assertEqual(count,0)

    def test_removed_target_never_receives_job(self):
        result,count=self.advance(self.campaign(),dict(status='completed'),dict(id='another'))
        self.assertEqual(result['status'],'paused');self.assertEqual(count,0)

    def test_paused_campaign_does_not_touch_devices(self):
        row=self.campaign();row['status']='paused'
        with mock.patch.object(rollouts.db,'get_endpoints') as endpoints:
            self.assertEqual(rollouts.advance(row),row)
        endpoints.assert_not_called()

    def test_named_canary_does_not_dispatch_an_unnamed_target(self):
        row=self.campaign('waiting');row['targets']['endpoint']['canary']=False
        row['targets']['pilot']=dict(state='waiting',canary=True)
        with mock.patch.object(rollouts.db,'get_endpoints',return_value=[self.endpoint,dict(self.endpoint,id='pilot')]),mock.patch.object(rollouts.db,'get_build_request',return_value={}),mock.patch.object(rollouts,'pinned_payload',return_value=dict(version='2.0.0')),mock.patch.object(rollouts.db,'get_active_remote_session',return_value=None),mock.patch.object(rollouts.db,'has_inflight_job',return_value=False),mock.patch.object(rollouts.db,'_patch'),mock.patch.object(rollouts.db,'get_company_by_id',return_value={}),mock.patch.object(rollouts.db,'encrypt_field',return_value='encrypted'),mock.patch.object(rollouts.db,'_rpc',return_value=[dict(id='pilot-job')]) as dispatch:
            rollouts.advance(row,self.now)
        self.assertEqual(dispatch.call_count,1)
        self.assertEqual(dispatch.call_args.args[1]['p_endpoint'],'pilot')


class SupersessionDatabase:
    """A stateful REST/lease boundary, including commit-before-response loss."""
    def __init__(self):
        self.company=dict(id='tenant',is_active=True,auto_update_agents=True)
        self.old=dict(id='old',status='completed',agent_version='2.6.59',target_platform='windows-amd64',sha256='a'*64)
        self.new=dict(id='new',status='completed',agent_version='2.6.60',target_platform='windows-amd64',sha256='b'*64)
        self.row=dict(id='campaign',company_id='tenant',created_by='human-admin',build_id='old',status='paused',
                      pause_reason='Worker encountered an error. Inspect device jobs and server logs before resuming.',
                      created_at='2026-10-04T19:12:57+00:00',lease_token=None,lease_until=None,
                      targets={'endpoint':dict(state='verified',job_id='done',previous_version='2.6.58'),
                               'waiting':dict(state='waiting',previous_version='2.6.36')})
        self.jobs={'done':dict(id='done',company_id='tenant',endpoint_id='endpoint',type='UPDATE_AGENT',status='completed',exit_code=0)}
        self.endpoints=[dict(id=key,company_id='tenant',status='online',platform='windows',arch='amd64',agent_version='2.6.59') for key in self.row['targets']]
        self.patches=[]
        self.claims=[]
        self.cancel_attempts=0
        self.after_claim=None
        self.cancel_failure=None
        self.claim_allowed=True
        self.claim_response_lost=False
        self.terminal_read_failure=False
        self.before_cancel=None

    def campaigns(self,*args,**kwargs):
        return [copy.deepcopy(self.row)] if self.row['status'] in rollouts.ACTIVE else []

    def build(self,key):
        return copy.deepcopy({'old':self.old,'new':self.new}.get(key))

    def latest(self,target):
        return copy.deepcopy(self.new) if target=='windows-amd64' else None

    def get(self,path,*args,**kwargs):
        if path.split('?',1)[0]!='agent_rollouts':
            raise AssertionError('Unexpected table read: '+path.split('?',1)[0])
        if self.terminal_read_failure and self.row['status']=='cancelled':
            raise TimeoutError('Terminal receipt unavailable')
        return [copy.deepcopy(self.row)] if self.matches(path) else []

    def matches(self,path):
        filters=parse_qs(path.partition('?')[2])
        for key,values in filters.items():
            if key in {'select','limit','order'}:
                continue
            value=unquote(values[0])
            if value.startswith('eq.') and str(self.row.get(key))!=value[3:]:
                return False
            if value.startswith('gt.'):
                actual=self.row.get(key)
                threshold=datetime.now(timezone.utc) if value[3:]=='now()' else datetime.fromisoformat(value[3:].replace('Z','+00:00'))
                if not actual or datetime.fromisoformat(actual.replace('Z','+00:00'))<=threshold:
                    return False
            if value=='is.null' and self.row.get(key) is not None:
                return False
        return True

    def rpc(self,name,params):
        if name!='claim_agent_rollout':
            raise AssertionError('Unexpected mutating RPC: '+name)
        self.claims.append(copy.deepcopy(params))
        if not self.claim_allowed or self.row.get('lease_token'):
            return False
        self.row.update(lease_token=params['p_token'],lease_until=(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat())
        if self.after_claim:
            self.after_claim()
        if self.claim_response_lost:
            raise TimeoutError('Claim committed response lost')
        return True

    def patch(self,path,data,*args,**kwargs):
        self.patches.append((path,copy.deepcopy(data)))
        cancel=data.get('status')=='cancelled'
        if cancel:
            self.cancel_attempts+=1
            if self.before_cancel:
                self.before_cancel()
            if self.cancel_failure=='before_commit':
                raise TimeoutError('Response unavailable before commit')
        if not self.matches(path):
            return []
        self.row.update(copy.deepcopy(data))
        if cancel and self.cancel_failure=='after_commit':
            raise TimeoutError('Committed response lost')
        return [copy.deepcopy(self.row)]


class AgentCampaignSupersessionTests(unittest.TestCase):
    def setUp(self):
        self.state=SupersessionDatabase()
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        directory=pathlib.Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        executable=b'approved executable fixture'
        self.state.new['sha256']=hashlib.sha256(executable).hexdigest()
        (directory/'new').mkdir()
        with zipfile.ZipFile(directory/'new'/'agent-installer.zip','w') as archive:
            archive.writestr('warden-agent.exe',executable)
            archive.writestr('WardenCredentialProvider.dll',b'approved companion fixture')
        self.stack.enter_context(mock.patch.object(rollouts.config,'AGENT_DIST_DIR',directory))
        replacements={
            'get_auto_update_company':lambda:copy.deepcopy(self.state.company) if self.state.company.get('auto_update_agents') else None,
            'get_company_by_id':lambda key:copy.deepcopy(self.state.company) if key=='tenant' else None,
            'get_build_request':self.state.build,
            'get_latest_completed_build':self.state.latest,
            'get_job':lambda key,**kw:copy.deepcopy(self.state.jobs.get(key)),
            'get_endpoints':lambda company_id,**kw:copy.deepcopy(self.state.endpoints),
            '_get':self.state.get,'_rpc':self.state.rpc,'_patch':self.state.patch,
        }
        for name,implementation in replacements.items():
            self.stack.enter_context(mock.patch.object(rollouts.db,name,side_effect=implementation))
        self.stack.enter_context(mock.patch.object(rollouts,'campaigns',side_effect=self.state.campaigns))
        self.audit=self.stack.enter_context(mock.patch.object(rollouts.db,'audit'))
        self.stack.enter_context(mock.patch('services.entitlements.check_job',return_value=mock.Mock(allowed=True)))
        self.original=copy.deepcopy(self.state.row)
        self.original_jobs=copy.deepcopy(self.state.jobs)

    def reconcile(self):
        return rollouts.reconcile_obsolete_campaigns()

    def assert_preserved(self):
        self.assertEqual(self.state.row['status'],self.original['status'])
        self.assertEqual(self.state.row['targets'],self.original['targets'])
        self.assertEqual(self.state.jobs,self.original_jobs)
        self.assertEqual(self.state.cancel_attempts,0)

    def test_old_worker_error_hold_releases_without_rewriting_history_or_jobs(self):
        # Reproduce the observed old hold: 32 verified jobs and two offline
        # devices still waiting. Supersession is not a new health receipt.
        self.state.row['targets']={str(i):dict(state='verified',job_id='done-'+str(i),previous_version='2.6.58') for i in range(32)}
        self.state.row['targets'].update({str(i):dict(state='waiting',previous_version='2.6.36') for i in range(32,34)})
        self.state.jobs={'done-'+str(i):dict(id='done-'+str(i),company_id='tenant',endpoint_id=str(i),type='UPDATE_AGENT',status='completed',exit_code=0) for i in range(32)}
        self.state.endpoints=[dict(id=key,company_id='tenant',status='online' if int(key)<32 else 'offline',platform='windows',agent_version='2.6.59') for key in self.state.row['targets']]
        self.original=copy.deepcopy(self.state.row)
        self.original_jobs=copy.deepcopy(self.state.jobs)
        self.assertEqual(self.reconcile(),{'campaign'})
        self.assertEqual(self.state.row['status'],'cancelled')
        self.assertIsNone(self.state.row['lease_token'])
        self.assertIsNone(self.state.row['lease_until'])
        self.assertEqual(self.state.row['targets'],self.original['targets'])
        self.assertEqual(self.state.row['created_at'],self.original['created_at'])
        self.assertEqual(self.state.jobs,self.original_jobs)
        self.assertIn('2.6.60',self.state.row['pause_reason'])
        self.audit.assert_called_once()
        self.assertEqual(self.reconcile(),set())
        self.assertEqual(self.state.cancel_attempts,1)
        old_token=self.state.claims[0]['p_token']
        self.assertEqual(self.state.patch('agent_rollouts?id=eq.campaign&lease_token=eq.'+old_token,{'status':'expanding'}),[])
        self.assertEqual(self.state.row['status'],'cancelled')

    def test_active_campaign_allows_running_old_job_to_drain_unchanged(self):
        self.state.row.update(status='expanding',pause_reason=None)
        self.state.jobs['done']['status']='running'
        original_job=copy.deepcopy(self.state.jobs['done'])
        self.assertEqual(self.reconcile(),{'campaign'})
        self.assertEqual(self.state.jobs['done'],original_job)
        self.assertEqual(self.state.row['targets'],self.original['targets'])

    def test_equal_older_and_invalid_versions_do_not_release_protection(self):
        for version in ('2.6.59','2.6.9','latest','2.6.60-beta','2.6','',None):
            with self.subTest(version=version):
                self.state.new['agent_version']=version
                self.assertEqual(self.reconcile(),set())
                self.assert_preserved()
        self.state.new['agent_version']='2.6.60'
        self.state.old['agent_version']='invalid'
        self.assertEqual(self.reconcile(),set())
        self.assert_preserved()

    def test_numeric_order_handles_double_digit_patch(self):
        self.state.old['agent_version']='2.6.9'
        self.state.new['agent_version']='2.6.10'
        self.assertEqual(self.reconcile(),{'campaign'})

    def test_other_platform_opted_out_tenant_and_missing_hash_preserve_hold(self):
        cases=(('target_platform','linux-amd64'),('status','pending'),('sha256',None),('deletion_requested_at','2026-10-11T00:00:00+00:00'))
        original_new=copy.deepcopy(self.state.new)
        for field,value in cases:
            with self.subTest(field=field):
                self.state.new=copy.deepcopy(original_new);self.state.new[field]=value
                self.assertEqual(self.reconcile(),set());self.assert_preserved()
        self.state.new=original_new
        self.state.company['auto_update_agents']=False
        self.assertEqual(self.reconcile(),set());self.assert_preserved()
        self.state.company['auto_update_agents']=True
        self.state.row['company_id']='other'
        self.assertEqual(self.reconcile(),set());self.assert_preserved()

    def test_unavailable_or_corrupt_replacement_does_not_release_hold(self):
        self.state.new['sha256']='0'*64
        self.assertEqual(self.reconcile(),set());self.assert_preserved()
        self.state.new['sha256']=hashlib.sha256(b'approved executable fixture').hexdigest()
        path=rollouts.config.AGENT_DIST_DIR/'new'/'agent-installer.zip'
        path.unlink()
        self.assertEqual(self.reconcile(),set());self.assert_preserved()

    def test_manual_failure_timeout_and_rollback_pauses_are_preserved(self):
        for reason in (None,'Paused for operator review','An update failed; remaining devices were not dispatched',
                       'Device did not report a healthy expected-version heartbeat within 10 minutes',
                       'Rollback complete. Cancel this campaign to release its devices to normal auto-updates.'):
            with self.subTest(reason=reason):
                self.state.row['pause_reason']=reason
                self.assertEqual(self.reconcile(),set());self.assert_preserved()
        self.state.row['pause_reason']=self.original['pause_reason']
        for state in ('failed','rollback_queued','rolled_back','unknown'):
            with self.subTest(target_state=state):
                self.state.row['targets']['endpoint']['state']=state
                self.assertEqual(self.reconcile(),set())
                self.assertEqual(self.state.row['status'],'paused')
                self.assertEqual(self.state.cancel_attempts,0)
        self.state.row['targets']=copy.deepcopy(self.original['targets'])
        self.state.row['status']='rolling_back'
        self.assertEqual(self.reconcile(),set());self.assertEqual(self.state.cancel_attempts,0)

    def test_paused_worker_error_rejects_incomplete_missing_foreign_or_wrong_job(self):
        original=copy.deepcopy(self.state.jobs['done'])
        for field,value in (('status','pending'),('status','approved'),('status','running'),('status','failed'),
                            ('status','cancelled'),('company_id','other'),('endpoint_id','foreign'),('type','REINSTALL_AGENT'),
                            ('exit_code',1),('exit_code','invalid')):
            with self.subTest(field=field,value=value):
                self.state.jobs['done']=dict(original,**{field:value})
                self.assertEqual(self.reconcile(),set());self.assertEqual(self.state.cancel_attempts,0)
        self.state.jobs.clear()
        self.assertEqual(self.reconcile(),set());self.assertEqual(self.state.cancel_attempts,0)

    def test_claim_contention_cannot_change_campaign(self):
        self.state.claim_allowed=False
        self.assertEqual(self.reconcile(),set());self.assert_preserved()

    def test_a_new_owner_or_expired_lease_cannot_be_cancelled(self):
        self.state.after_claim=lambda:self.state.row.update(lease_token='new-owner')
        self.assertEqual(self.reconcile(),set());self.assert_preserved()
        self.assertEqual(self.state.row['lease_token'],'new-owner')
        self.state.row['lease_token']=None
        self.state.after_claim=lambda:self.state.row.update(lease_until=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat())
        self.assertEqual(self.reconcile(),set())
        self.assertEqual(self.state.row['status'],'paused')

    def test_missing_creator_does_not_make_a_human_pause_automatic(self):
        self.state.row.update(created_by=None,pause_reason=None)
        self.assertEqual(self.reconcile(),set());self.assert_preserved()

    def test_new_owner_between_fresh_read_and_cas_is_never_cancelled_or_released(self):
        self.state.before_cancel=lambda:self.state.row.update(lease_token='new-owner',pause_reason='Paused for operator review')
        self.assertEqual(self.reconcile(),set())
        self.assertEqual(self.state.cancel_attempts,1)
        self.assertEqual(self.state.row['status'],'paused')
        self.assertEqual(self.state.row['lease_token'],'new-owner')
        self.assertEqual(self.state.row['pause_reason'],'Paused for operator review')
        self.assertEqual(self.state.row['targets'],self.original['targets'])
        self.audit.assert_not_called()

    def test_endpoint_ownership_or_platform_change_preserves_campaign(self):
        original=copy.deepcopy(self.state.endpoints)
        for field,value in (('company_id','other'),('platform','linux')):
            with self.subTest(field=field):
                self.state.endpoints=copy.deepcopy(original)
                self.state.endpoints[0][field]=value
                self.assertEqual(self.reconcile(),set());self.assert_preserved()

    def test_disabled_company_or_fresh_entitlement_denial_preserves_hold(self):
        self.state.company['is_active']=False
        self.assertEqual(self.reconcile(),set());self.assert_preserved()
        self.state.company['is_active']=True
        with mock.patch('services.entitlements.check_job',return_value=mock.Mock(allowed=False)):
            self.assertEqual(self.reconcile(),set());self.assert_preserved()

    def test_every_referenced_job_is_checked_before_releasing_worker_error_hold(self):
        self.state.row['targets']['last']=dict(state='verified',job_id='failed-last')
        self.state.jobs['failed-last']=dict(id='failed-last',company_id='tenant',endpoint_id='last',type='UPDATE_AGENT',status='failed')
        self.state.endpoints.append(dict(id='last',company_id='tenant',platform='windows',agent_version='2.6.59'))
        self.assertEqual(self.reconcile(),set())
        self.assertEqual(self.state.row['status'],'paused')
        self.assertEqual(self.state.cancel_attempts,0)

    def test_opt_in_revocation_or_replacement_withdrawal_after_claim_preserves_hold(self):
        self.state.after_claim=lambda:self.state.company.update(auto_update_agents=False)
        self.assertEqual(self.reconcile(),set());self.assert_preserved()
        self.state.company['auto_update_agents']=True
        self.state.after_claim=lambda:self.state.new.update(deletion_requested_at='2026-10-11T00:00:00+00:00')
        self.assertEqual(self.reconcile(),set());self.assert_preserved()

    def test_lost_committed_response_is_reconciled_without_cancel_retry(self):
        self.state.cancel_failure='after_commit'
        self.assertEqual(self.reconcile(),{'campaign'})
        self.assertEqual(self.state.row['status'],'cancelled')
        self.assertEqual(self.state.cancel_attempts,1)
        self.assertEqual(self.state.jobs,self.original_jobs)

    def test_timeout_before_commit_leaves_campaign_protected_without_cancel_retry(self):
        self.state.cancel_failure='before_commit'
        self.assertEqual(self.reconcile(),set())
        self.assertEqual(self.state.row['status'],'paused')
        self.assertEqual(self.state.cancel_attempts,1)
        self.assertEqual(self.state.row['targets'],self.original['targets'])

    def test_lost_claim_response_releases_only_own_lease_without_mutation_retry(self):
        self.state.claim_response_lost=True
        self.assertEqual(self.reconcile(),set())
        self.assert_preserved()
        self.assertEqual(len(self.state.claims),1)
        self.assertIsNone(self.state.row['lease_token'])

    def test_unreadable_terminal_receipt_does_not_retry_cancellation_or_claim_success(self):
        self.state.cancel_failure='after_commit'
        self.state.terminal_read_failure=True
        self.assertEqual(self.reconcile(),set())
        self.assertEqual(self.state.cancel_attempts,1)
        self.assertEqual(self.state.row['status'],'cancelled')
        self.assertEqual(self.state.jobs,self.original_jobs)
        self.audit.assert_not_called()


if __name__=='__main__':
    unittest.main()
