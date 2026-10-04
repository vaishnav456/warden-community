import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid
from flask import Flask, g
from services import agent_modules as modules
from routes import agent_api, settings


def bare(function):
    while hasattr(function, '__wrapped__'):
        function = function.__wrapped__
    return function


class AgentModuleTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.endpoint = dict(id=str(uuid.uuid4()), company_id=str(uuid.uuid4()))
        self.limiter = patch.object(agent_api, 'check_rate_limit', return_value=True)
        self.limiter.start()
        self.addCleanup(self.limiter.stop)

    def test_optional_download_requires_both_explicit_permissions(self):
        for row in (None, dict(enabled=False), dict(enabled='true')):
            with patch.object(modules, 'policy', return_value=row), patch.object(modules, 'entitled', return_value=True):
                self.assertFalse(modules.allowed(self.endpoint['company_id']))
        with patch.object(modules, 'policy', return_value=dict(enabled=True)):
            for entitled in (False, True):
                with patch.object(modules, 'entitled', return_value=entitled):
                    self.assertEqual(modules.allowed(self.endpoint['company_id']), entitled)

    def test_legacy_compatibility_does_not_grant_downloads(self):
        with patch.object(modules, 'policy', return_value=None):
            self.assertTrue(modules.legacy_allowed(self.endpoint['company_id']))
            self.assertFalse(modules.allowed(self.endpoint['company_id']))

    def test_revocation_blocks_ticket_actions_without_entering_handler(self):
        called = []
        handler = modules.helpdesk_access(lambda: called.append(True))
        with self.app.test_request_context():
            g.endpoint = self.endpoint
            with patch.object(modules, 'legacy_allowed', return_value=False):
                response, code = handler()
                self.assertEqual(code, 403)
                self.assertEqual(response.json['error'], 'module_not_allowed')
        self.assertFalse(called)

    def test_signed_payload_is_bound_and_short_lived(self):
        release = dict(release_id=str(uuid.uuid4()), release_sequence=1, version='1.0.0',
                       min_core_version='2.7.0', sha256='a'*64, size_bytes=100)
        with patch.object(modules.config, 'SERVER_URL', 'https://local-community.example'), patch.object(modules, 'sign_canonical_payload', return_value=b'fixture'):
            result = modules.grant(self.endpoint, release)
        value = json.loads(base64.b64decode(result['payload_b64']))
        self.assertEqual(value['endpoint_id'], self.endpoint['id'])
        self.assertEqual(value['tenant_id'], self.endpoint['company_id'])
        self.assertEqual(value['expires_at']-value['issued_at'], 300)
        self.assertTrue(value['download_url'].startswith('https://local-community.example/'))
        self.assertEqual(value['capabilities'], modules.CAPABILITIES)
        with patch.object(modules.config, 'SERVER_URL', 'http://insecure.example'):
            with self.assertRaises(ValueError): modules.grant(self.endpoint, release)

    def test_corrupt_release_is_never_served(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blob = b'nonexecutable test fixture'
            value = dict(release_id=str(uuid.uuid4()), release_sequence=1, version='1.0.0',
                         min_core_version='2.7.0', sha256=hashlib.sha256(blob).hexdigest(), size_bytes=len(blob))
            path = root/(value['release_id']+'.exe')
            path.write_bytes(blob)
            (root/'helpdesk.json').write_text(json.dumps(value))
            with patch.object(modules.config, 'AGENT_MODULE_PACKAGE_DIR', directory):
                self.assertEqual(modules.release()[0], value)
                path.write_bytes(b'x'*len(blob))
                with self.assertRaises(ValueError): modules.release()
                path.write_bytes(blob)
                for key, bad in [('release_id','../../evil'), ('release_sequence',True), ('size_bytes',2**30), ('version','1.0.0;command'), ('sha256','wrong')]:
                    (root/'helpdesk.json').write_text(json.dumps({**value, key:bad}))
                    with self.assertRaises((ValueError, TypeError)): modules.release()

    def test_manifest_and_package_recheck_live_authorization(self):
        for function, args in [(agent_api.helpdesk_module_manifest, ()), (agent_api.helpdesk_module_package, (str(uuid.uuid4()),))]:
            with self.app.test_request_context():
                g.endpoint = self.endpoint
                with patch.object(modules, 'verify_request_proof'), patch.object(modules, 'allowed', return_value=False), patch.object(modules, 'release') as release:
                    _, code = bare(function)(*args)
                    self.assertEqual(code, 403)
                    release.assert_not_called()

    def test_api_key_without_device_proof_cannot_download(self):
        with self.app.test_request_context(headers={'X-Agent-Key':'fixture'}):
            g.endpoint = self.endpoint
            with patch.object(modules, 'allowed') as allowed:
                _, code = bare(agent_api.helpdesk_module_manifest)()
                self.assertEqual(code, 401)
                allowed.assert_not_called()

    def test_admin_policy_uses_authenticated_tenant_and_actor(self):
        self.app.secret_key = 'test-only'
        with self.app.test_request_context(method='POST', data={'enabled':'true','company_id':'attacker','updated_by':'attacker'}):
            g.company = dict(id=self.endpoint['company_id'])
            g.admin = dict(id='trusted-admin')
            with patch.object(modules.db, '_post') as write, patch.object(modules.db, 'audit'), patch.object(settings, 'url_for', return_value='/settings/agent-modules'):
                bare(settings.agent_modules)()
            self.assertEqual(write.call_args.args[1]['company_id'], g.company['id'])
            self.assertEqual(write.call_args.args[1]['updated_by'], 'trusted-admin')
