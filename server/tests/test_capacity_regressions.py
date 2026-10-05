import asyncio
import pathlib
import sys
import unittest
from unittest.mock import patch
from flask import Flask, g
SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))
import db
from services import ws_proxy

class CapacityRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_home_relay_admits_slow_http_with_spare_workers(self):
        from services.load_control import LoadController
        control = LoadController()
        control.active_http = 4
        for _ in range(20):
            control.http_latency = 1.9
            control.observe(cpu=.01, memory=.21, lag=.001)
        with patch.object(ws_proxy, 'load_controller', control):
            try:
                pair = await ws_proxy._attach_home_peer('slow-http-home', 'initiator', object())
                self.assertIsNotNone(pair)
                self.assertIs(await ws_proxy._attach_home_peer('slow-http-home', 'target', object()), pair)
                self.assertIsNone(await ws_proxy._attach_home_peer('slow-http-home', 'initiator', object()))
            finally:
                await ws_proxy._cleanup_home_pair('slow-http-home')

    async def test_pressure_preserves_existing_remote_and_home_pairs(self):
        first = await ws_proxy._attach_peer('pressure-existing', 'browser', object(), 'a')
        home = await ws_proxy._attach_home_peer('pressure-home', 'initiator', object())
        try:
            with patch.object(ws_proxy.load_controller, 'busy', True):
                self.assertIs(await ws_proxy._attach_peer('pressure-existing', 'agent', object(), 'a'), first)
                with self.assertRaises(ws_proxy.RelayCapacityExceeded):
                    await ws_proxy._attach_peer('pressure-new', 'browser', object(), 'b')
                self.assertIs(await ws_proxy._attach_home_peer('pressure-home', 'target', object()), home)
                self.assertIsNone(await ws_proxy._attach_home_peer('pressure-home-new', 'target', object()))
        finally:
            await ws_proxy._cleanup_pair('pressure-existing', first)
            await ws_proxy._cleanup_home_pair('pressure-home')

    async def test_global_capacity_still_allows_second_peer(self):
        with patch.object(ws_proxy,'MAX_REMOTE_RELAY_PAIRS',1):
            first=await ws_proxy._attach_peer('capacity-limit','browser',object(),'tenant-a')
            self.assertIs(await ws_proxy._attach_peer('capacity-limit','agent',object(),'tenant-a'),first)
            with self.assertRaises(ws_proxy.RelayCapacityExceeded):
                await ws_proxy._attach_peer('capacity-excess','browser',object(),'tenant-b')
            self.assertNotIn('capacity-excess',ws_proxy._pairs)
        await ws_proxy._cleanup_pair('capacity-limit',first)

    async def test_tenant_capacity_does_not_block_another_tenant(self):
        with patch.object(ws_proxy.load_controller,'pressure',.85):
            first=await ws_proxy._attach_peer('tenant-limit-a','browser',object(),'tenant-a')
            other=await ws_proxy._attach_peer('tenant-limit-b','browser',object(),'tenant-b')
            with self.assertRaises(ws_proxy.RelayCapacityExceeded):
                await ws_proxy._attach_peer('tenant-excess-a','browser',object(),'tenant-a')
        await ws_proxy._cleanup_pair('tenant-limit-a',first)
        await ws_proxy._cleanup_pair('tenant-limit-b',other)

    async def test_closing_pair_rejects_reattachment(self):
        pair = ws_proxy._Pair()
        pair.closing = True
        ws_proxy._pairs['closing-test'] = pair
        try:
            self.assertIsNone(await ws_proxy._attach_peer('closing-test','agent',object()))
            self.assertIsNone(pair.agent_ws)
        finally:
            ws_proxy._pairs.pop('closing-test',None)

    async def test_old_cleanup_cannot_remove_new_pair(self):
        old, new = ws_proxy._Pair(), ws_proxy._Pair()
        ws_proxy._pairs['identity-test'] = new
        await ws_proxy._cleanup_pair('identity-test', old)
        self.assertIs(ws_proxy._pairs['identity-test'],new)
        await ws_proxy._cleanup_pair('identity-test',new)
        self.assertNotIn('identity-test',ws_proxy._pairs)

    async def test_real_transport_accepts_4k_sized_frame(self):
        import websockets
        session = dict(id='capacity-session', endpoint_id='capacity-endpoint', company_id='tenant',
                       admin_id='synthetic-admin', owner_access_token_version=0,
                       status='active', consent_required=True, consent_status='approved',
                       capabilities={'view':True,'control':False})
        payload = b'JPEG-fixture' + bytes(1988742)
        self.assertLess(len(payload),ws_proxy.MAX_RELAY_MESSAGE_BYTES)
        with (
             patch.object(ws_proxy.db,'get_remote_session_by_token',return_value=session),
             patch.object(ws_proxy.db,'get_remote_session',return_value=session),
             patch.object(ws_proxy.db,'get_admin_by_id',return_value=dict(id='synthetic-admin',company_id='tenant',role='technician',is_active=True,access_token_version=0)),
             patch.object(ws_proxy.db,'get_endpoint_by_api_key_hash',return_value={'id':'capacity-endpoint'}),
             patch.object(ws_proxy.config,'REQUIRE_CLIENT_CERT',False),
             patch.object(ws_proxy.db,'close_remote_session'), patch.object(ws_proxy.db,'_patch')
        ):
            async with websockets.serve(ws_proxy._handle,'127.0.0.1',0,
                max_size=ws_proxy.MAX_RELAY_MESSAGE_BYTES,max_queue=ws_proxy.MAX_RELAY_QUEUE) as server:
                port=server.sockets[0].getsockname()[1]
                async with websockets.connect(f'ws://127.0.0.1:{port}/agent-relay/capacity-session',
                    additional_headers={'X-Agent-Key':'synthetic-key'},compression=None) as agent:
                    async with websockets.connect(f'ws://127.0.0.1:{port}/remote-ws/capacity-endpoint',
                        additional_headers={'Cookie':'warden_remote=synthetic-token'},
                        max_size=ws_proxy.MAX_RELAY_MESSAGE_BYTES,compression=None) as browser:
                        await agent.send(payload)
                        self.assertEqual(await asyncio.wait_for(browser.recv(),5),payload)
        ws_proxy._pairs.pop('capacity-session',None)

class RequestCompanyCacheTests(unittest.TestCase):
    def setUp(self):
        self.app=Flask(__name__)

    def test_repeated_reads_are_request_scoped_and_do_not_alias(self):
        with patch.object(db,'_get',return_value=[{'id':'tenant','is_active':True}]) as read:
            with self.app.test_request_context('/'):
                first=db.get_company_by_id('tenant')
                first['is_active']=False
                self.assertTrue(db.get_company_by_id('tenant')['is_active'])
                self.assertEqual(read.call_count,1)
            with self.app.test_request_context('/'):
                db.get_company_by_id('tenant')
            self.assertEqual(read.call_count,2)

    def test_tenants_have_separate_cache_entries(self):
        with self.app.test_request_context('/'),patch.object(db,'_get',side_effect=[[{'id':'a'}],[{'id':'b'}]]) as read:
            self.assertEqual(db.get_company_by_id('a')['id'],'a')
            self.assertEqual(db.get_company_by_id('b')['id'],'b')
            self.assertEqual(read.call_count,2)

    def test_company_mutation_invalidates_request_entry(self):
        with self.app.test_request_context('/'),patch.object(db,'_get',side_effect=[[{'id':'a','is_active':True}],[{'id':'a','is_active':False}]]),patch.object(db,'_patch',return_value=[{'id':'a'}]):
            db.get_company_by_id('a')
            db.update_company('a',{'is_active':False})
            self.assertFalse(db.get_company_by_id('a')['is_active'])

    def test_background_reads_are_not_cached(self):
        with patch.object(db,'_get',return_value=[{'id':'a'}]) as read:
            db.get_company_by_id('a');db.get_company_by_id('a')
            self.assertEqual(read.call_count,2)

    def test_authenticated_binding_reused_only_for_matching_endpoint(self):
        with self.app.test_request_context('/'),patch.object(db,'_get',return_value=[{'company_id':'b'}]) as read,patch.object(db,'get_company_by_id',side_effect=lambda cid:{'id':cid}):
            g.endpoint={'id':'endpoint-a','company_id':'a'}
            self.assertEqual(db._endpoint_company('endpoint-a')['id'],'a')
            read.assert_not_called()
            self.assertEqual(db._endpoint_company('endpoint-b')['id'],'b')
            read.assert_called_once()
