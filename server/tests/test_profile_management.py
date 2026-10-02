import base64
import pathlib
import sys
import unittest
import urllib.error
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import mock

from flask import Flask, g

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from routes import users, directory

PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aXioAAAAASUVORK5CYII='


def raw(view):
    while hasattr(view, '__wrapped__'):
        view = view.__wrapped__
    return view


class ProfileManagementTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.admin = dict(id='a1', company_id='c1', full_name='Owner', email='owner@example.com',
                          role='company_admin', branch_id=None, password_hash='hash')
        self.target = dict(self.admin, id='a2', email='other@example.com')
        self.company = {'id': 'c1'}
        self.admission = mock.patch('services.tenant_storage.admission', return_value=nullcontext()).start()
        self.addCleanup(mock.patch.stopall)

    def context(self, path, body=None):
        ctx = self.app.test_request_context(path, method='POST', json=body or {})
        ctx.push()
        self.addCleanup(ctx.pop)
        g.admin, g.company = self.admin, self.company
        return ctx

    def test_self_profile_changes_name_without_revoking_sessions(self):
        self.context('/users/profile', {'full_name': "Owner O'Neil"})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'update_admin') as update, \
             mock.patch.object(users.db, 'revoke_all_tokens_for_admin') as revoke, \
             mock.patch.object(users.db, 'audit'):
            response = raw(users.profile)()
        self.assertTrue(response.get_json()['ok'])
        self.assertNotIn('profile_photo', update.call_args.args[1])
        self.assertEqual(update.call_args.args[1]['full_name'], "Owner O'Neil")
        revoke.assert_not_called()

    def test_own_email_change_requires_current_password(self):
        self.context('/users/profile', {'full_name': 'Owner', 'email': 'new@example.com'})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=None), \
             mock.patch('routes.auth._check_password', return_value=False), \
             mock.patch.object(users.db, 'update_admin') as update:
            _, status = raw(users.profile)()
        self.assertEqual(status, 400)
        update.assert_not_called()

    def test_authenticated_own_email_change_revokes_sessions(self):
        self.context('/users/profile', {'full_name': 'Owner', 'email': 'NEW@example.com', 'current_password': 'verified'})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=None), \
             mock.patch('routes.auth._check_password', return_value=True), \
             mock.patch.object(users.db, 'update_admin') as update, \
             mock.patch.object(users.db, 'revoke_all_tokens_for_admin') as revoke, \
             mock.patch.object(users.db, 'audit'):
            response = raw(users.profile)()
        self.assertTrue(response.get_json()['sign_in_required'])
        self.assertEqual(update.call_args.args[1]['email'], 'new@example.com')
        revoke.assert_called_once_with('a1')

    def test_admin_photo_is_encrypted_with_record_bound_purpose(self):
        self.context('/users/profile', {'full_name': 'Owner', 'profile_photo': PNG})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'update_admin') as update, \
             mock.patch.object(users.db, 'audit'), \
             mock.patch('services.platform_secrets.encrypt_platform_field', return_value='encrypted') as encrypt:
            raw(users.profile)()
        encrypt.assert_called_once_with('a1', 'admin.profile_photo', PNG)
        self.assertEqual(update.call_args.args[1]['profile_photo'], 'encrypted')

    def test_photo_removal_is_explicit(self):
        self.context('/users/profile', {'full_name': 'Owner', 'profile_photo': ''})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'update_admin') as update, mock.patch.object(users.db, 'audit'):
            raw(users.profile)()
        self.assertIsNone(update.call_args.args[1]['profile_photo'])

    def test_replacing_admin_photo_overwrites_existing_value(self):
        self.context('/users/profile', {'full_name': 'Owner', 'profile_photo': PNG})
        stored = dict(self.admin, profile_photo='old-encrypted-photo', profile_photo_mime='image/png')
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'get_admin_by_id', return_value=stored), \
             mock.patch.object(users.db, 'update_admin', side_effect=lambda admin_id, fields: stored.update(fields)) as update, \
             mock.patch.object(users.db, 'audit'), \
             mock.patch('services.platform_secrets.encrypt_platform_field', return_value='new-encrypted-photo'):
            raw(users.profile)()
        update.assert_called_once()
        self.assertEqual(stored['profile_photo'], 'new-encrypted-photo')
        self.assertNotIn('old-encrypted-photo', stored.values())

    def test_photo_growth_is_computed_under_the_tenant_lease(self):
        self.context('/users/profile', {'full_name': 'Owner', 'profile_photo': PNG})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'get_admin_by_id', return_value=dict(self.admin, profile_photo='old')), \
             mock.patch.object(users.db, 'update_admin'), mock.patch.object(users.db, 'audit'), \
             mock.patch('services.platform_secrets.encrypt_platform_field', return_value='encrypted-photo'):
            raw(users.profile)()
            company, delta = self.admission.call_args.args
            self.assertEqual(company, 'c1')
            self.assertEqual(delta(), len('encrypted-photo') - len('old'))

    def test_over_quota_photo_never_replaces_previous_photo(self):
        from services.tenant_storage import StorageError
        self.context('/users/profile', {'full_name': 'Owner', 'profile_photo': PNG})
        self.admission.side_effect = StorageError('storage_quota_exceeded', 'Full', 413)
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'update_admin') as update, \
             mock.patch('services.platform_secrets.encrypt_platform_field', return_value='encrypted'):
            with self.assertRaises(StorageError) as caught:
                raw(users.profile)()
        self.assertEqual(caught.exception.status, 413)
        update.assert_not_called()

    def test_directory_photo_replacement_uses_growth_not_full_size(self):
        identity = {'id': 'i1', 'profile_photo': PNG}
        self.context('/directory/identities/i1/profile', {'display_name': 'Updated', 'login_email': 'jane@example.com', 'profile_photo': PNG})
        with mock.patch.object(directory.db, 'get_warden_identity', return_value=identity), \
             mock.patch('services.entitlements.check_mutation', return_value=SimpleNamespace(allowed=True)), \
             mock.patch.object(directory, 'admission', return_value=nullcontext()) as lease, \
             mock.patch.object(directory.db, 'update_warden_identity'), mock.patch.object(directory.db, 'audit'):
            raw(directory.update_warden_identity_profile)('i1')
            self.assertEqual(lease.call_args.args[0], 'c1')
            self.assertEqual(lease.call_args.args[1](), 0)

    def test_invalid_photo_does_not_write(self):
        self.context('/users/profile', {'full_name': 'Owner', 'profile_photo': 'data:image/svg+xml,script'})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'update_admin') as update:
            _, status = raw(users.profile)()
        self.assertEqual(status, 400)
        update.assert_not_called()

    def test_duplicate_admin_email_is_rejected(self):
        self.context('/users/profile', {'full_name': 'Owner', 'email': self.target['email']})
        with mock.patch.object(users.db, 'get_admin_by_email', return_value=self.target):
            _, status = raw(users.profile)()
        self.assertEqual(status, 400)

    def test_self_role_changes_remain_blocked(self):
        self.context('/users/a1/update', {'full_name': 'Owner', 'role': 'technician'})
        with mock.patch.object(users.db, 'get_admin_by_id', return_value=self.admin), \
             mock.patch.object(users.db, 'get_admin_by_email', return_value=self.admin), \
             mock.patch.object(users.db, 'update_admin') as update:
            _, status = raw(users.update)('a1')
        self.assertEqual(status, 400)
        update.assert_not_called()

    def test_reset_own_password_uses_authenticated_change_flow(self):
        self.context('/users/a1/reset-password')
        with mock.patch.object(users.db, 'get_admin_by_id', return_value=self.admin), \
             mock.patch.object(users.db, 'update_admin_password') as update:
            _, status = raw(users.reset_password)('a1')
        self.assertEqual(status, 400)
        update.assert_not_called()

    def test_password_reset_returns_non_cached_generated_password(self):
        self.context('/users/a2/reset-password')
        with mock.patch.object(users.db, 'get_admin_by_id', return_value=self.target), \
             mock.patch.object(users, '_hash_password', return_value='hashed'), \
             mock.patch.object(users.db, 'update_admin_password') as update, \
             mock.patch.object(users.db, 'revoke_all_tokens_for_admin'), mock.patch.object(users.db, 'audit'):
            response = raw(users.reset_password)('a2')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertGreaterEqual(len(response.get_json()['new_password']), 12)
        update.assert_called_once_with('a2', 'hashed')

    def test_password_reset_rejects_bcrypt_byte_overflow(self):
        self.context('/users/a2/reset-password', {'new_password': '界' * 25})
        with mock.patch.object(users.db, 'get_admin_by_id', return_value=self.target):
            _, status = raw(users.reset_password)('a2')
        self.assertEqual(status, 400)

    def test_photo_cannot_be_read_across_tenants(self):
        self.context('/users/a2/photo')
        with mock.patch.object(users.db, 'get_admin_by_id', return_value=dict(self.target, company_id='other')):
            with self.assertRaises(Exception) as caught:
                raw(users.photo)('a2')
        self.assertEqual(caught.exception.code, 404)

    def test_identity_profile_keeps_password_and_windows_username(self):
        self.context('/directory/identities/i1/profile', {'display_name': 'Updated', 'login_email': 'NEW@example.com'})
        with mock.patch.object(directory.db, 'get_warden_identity', return_value={'id': 'i1', 'username': 'stable'}), \
             mock.patch('services.entitlements.check_mutation', return_value=SimpleNamespace(allowed=True)), \
             mock.patch.object(directory.db, 'update_warden_identity') as update, mock.patch.object(directory.db, 'audit'):
            response = raw(directory.update_warden_identity_profile)('i1')
        self.assertTrue(response.get_json()['ok'])
        self.assertEqual(update.call_args.args[2], {'display_name': 'Updated', 'login_email': 'new@example.com'})

    def test_identity_email_conflict_returns_clear_response(self):
        self.context('/directory/identities/i1/profile', {'display_name': 'Updated', 'login_email': 'taken@example.com'})
        conflict = urllib.error.HTTPError('url', 409, 'conflict', {}, None)
        with mock.patch.object(directory.db, 'get_warden_identity', return_value={'id': 'i1'}), \
             mock.patch('services.entitlements.check_mutation', return_value=SimpleNamespace(allowed=True)), \
             mock.patch.object(directory.db, 'update_warden_identity', side_effect=conflict):
            _, status = raw(directory.update_warden_identity_profile)('i1')
        self.assertEqual(status, 409)

    def test_identity_edit_checks_tenant_ownership(self):
        self.context('/directory/identities/i1/profile', {'display_name': 'Updated'})
        with mock.patch.object(directory.db, 'get_warden_identity', return_value=None) as lookup:
            with self.assertRaises(Exception) as caught:
                raw(directory.update_warden_identity_profile)('i1')
        lookup.assert_called_once_with('i1', 'c1')
        self.assertEqual(caught.exception.code, 404)

    def test_templates_use_data_attributes_for_names_and_show_self_edit(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        page = (root / 'templates/users/list.html').read_text(encoding='utf-8')
        self.assertIn('resetPassword($el.dataset.id, $el.dataset.name)', page)
        self.assertNotIn('a.full_name | tojson', page)
        self.assertIn('/settings#change-password', page)
        self.assertIn('Edit profile', page)
        js = (root / 'static/js/warden.js').read_text(encoding='utf-8')
        component = js.split('function usersListPage()', 1)[1].split('function patchManagementPage()', 1)[0]
        for field in ('editEmail:', 'editSelf:', 'editPhoto:', 'editPhotoPreview:'):
            self.assertIn(field, component)
