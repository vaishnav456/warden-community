import unittest
from unittest import mock
from datetime import datetime,timezone,timedelta
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


if __name__=='__main__':
    unittest.main()
