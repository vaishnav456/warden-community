import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes import endpoints, settings
from policy_settings import validate_setting_value, validate_settings_dict
from policy_templates import POLICY_BENCHMARKS


def _undecorated(view):
    while hasattr(view, "__wrapped__"):
        view = view.__wrapped__
    return view


class ApprovalClassificationTests(unittest.TestCase):
    def test_routine_policy_and_admin_work_do_not_require_escalation(self):
        routine = {
            "PUSH_LOCAL_POLICY", "CREATE_USER", "RESET_PASSWORD",
            "DISABLE_USER", "ENABLE_USER", "INSTALL_APP", "UNINSTALL_APP",
            "REVOKE_ELEVATION", "UPDATE_AGENT", "REINSTALL_AGENT",
        }
        self.assertTrue(routine.isdisjoint(endpoints.ESCALATION_REQUIRED_OPS))

    def test_high_risk_operations_still_require_escalation(self):
        self.assertEqual(
            endpoints.ESCALATION_REQUIRED_OPS,
            {
                "DELETE_USER", "RUN_CMD", "REBOOT", "SHUTDOWN",
                "UNINSTALL_AGENT",
                "ROTATE_TLS_PINS", "GRANT_ELEVATION", "CAPTURE_PACKETS",
                "ENABLE_BITLOCKER", "ROTATE_BITLOCKER_RECOVERY",
            },
        )


class BenchmarkMappingTests(unittest.TestCase):
    def test_warden_windows_baseline_is_reviewable_and_validated(self):
        benchmark = POLICY_BENCHMARKS["warden_windows_secure_baseline"]
        self.assertGreaterEqual(len(benchmark["settings"]), 20)
        self.assertIn("firewall_all_profiles_enabled", benchmark["settings"])
        self.assertIn("defender_realtime_protection_enabled", benchmark["settings"])
        self.assertIn("bitlocker_enabled", benchmark["checks"])
        validate_settings_dict(benchmark["settings"])

    def test_firewall_rules_support_application_ip_and_ports(self):
        value = """[{"name":"ERP egress","direction":"out","action":"allow","protocol":"tcp","program":"C:\\\\Program Files\\\\ERP\\\\erp.exe","remote_addresses":["10.20.0.0/16","203.0.113.8"],"remote_ports":["443"]}]"""
        self.assertTrue(validate_setting_value("windows_firewall_rules", value))

    def test_firewall_rules_reject_unsafe_program_and_bad_network(self):
        for value in (
            '[{"name":"Bad path","direction":"out","action":"allow","program":"..\\\\evil.exe"}]',
            '[{"name":"Bad IP","direction":"in","action":"block","remote_addresses":["not-an-ip"]}]',
        ):
            with self.assertRaises(ValueError):
                validate_setting_value("windows_firewall_rules", value)

    def test_firewall_rules_protect_warden_control_plane(self):
        for value in (
            '[{"name":"Block all egress","direction":"out","action":"block"}]',
            '[{"name":"Block Warden","direction":"out","action":"block","program":"C:\\\\Program Files\\\\WardenAgent\\\\warden-agent.exe"}]',
        ):
            with self.assertRaises(ValueError):
                validate_setting_value("windows_firewall_rules", value)


class AgentVersionTests(unittest.TestCase):
    def test_numeric_order_blocks_downgrades(self):
        from services.scheduler import compare_agent_versions
        self.assertGreater(compare_agent_versions("2.1.24", "2.1.23"), 0)
        self.assertEqual(compare_agent_versions("2.1.23", "2.1.23"), 0)
        self.assertLess(compare_agent_versions("2.1.9", "2.1.10"), 0)

    def test_ambiguous_version_is_rejected(self):
        from services.scheduler import compare_agent_versions
        with self.assertRaises(ValueError):
            compare_agent_versions("latest", "2.1.23")


class ScheduledJobRaceTests(unittest.TestCase):
    def test_scheduler_uses_atomic_job_creation(self):
        from services import scheduler
        scheduled = {
            "id": "schedule-1", "company_id": "company-1", "branch_id": None,
            "endpoint_id": "endpoint-1", "job_type": "COLLECT_SYSINFO",
            "payload": {}, "name": "Inventory",
        }
        endpoint = {"id": "endpoint-1", "company_id": "company-1", "branch_id": "branch-1", "status": "online"}
        with mock.patch("services.entitlements.check_job", return_value=mock.Mock(allowed=True)), \
             mock.patch.object(scheduler.db, "get_endpoint", return_value=endpoint), \
             mock.patch.object(scheduler.db, "create_system_job_once", return_value=None) as create_once, \
             mock.patch.object(scheduler.db, "create_job") as legacy_create:
            scheduler._dispatch_job(scheduled)
        create_once.assert_called_once_with(
            "company-1", "branch-1", "endpoint-1", "COLLECT_SYSINFO", {},
        )
        legacy_create.assert_not_called()

    def test_auto_update_waits_for_post_restart_heartbeat(self):
        from services import scheduler
        company = {"id": "company-1"}
        endpoint = {
            "id": "endpoint-1", "branch_id": "branch-1", "status": "online",
            "platform": "windows", "agent_version": "2.6.36",
        }
        build = {"agent_version": "2.6.37", "sha256": "a" * 64}
        with mock.patch.object(scheduler.db, "get_auto_update_company", return_value=company), \
             mock.patch.object(scheduler.db, "get_endpoints", return_value=[endpoint]), \
             mock.patch.object(scheduler.db, "endpoint_target_platform", return_value="windows-amd64"), \
               mock.patch.object(scheduler.db, "get_latest_completed_build", return_value=build), \
               mock.patch("services.agent_rollouts.campaigns", return_value=[]), \
               mock.patch.object(scheduler.db, "get_active_remote_session", return_value=None), \
             mock.patch.object(scheduler, "update_payload", return_value={"version": "2.6.37"}), \
             mock.patch.object(scheduler.db, "has_recent_job", return_value=True) as recent, \
             mock.patch.object(scheduler.db, "create_system_job_once") as create_once:
            scheduler._check_auto_updates()
        recent.assert_called_once_with("endpoint-1", "UPDATE_AGENT", minutes=15)
        create_once.assert_not_called()


class GroupPolicyDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_deploy_fans_out_one_job_per_active_endpoint(self):
        template = {
            "id": "template-1", "company_id": "company-1", "name": "Baseline",
            "settings": {"guest_account_enabled": False},
        }
        branch = {"id": "branch-1", "company_id": "company-1", "name": "HQ"}
        fleet = [
            {"id": "endpoint-1", "branch_id": "branch-1"},
            {"id": "endpoint-2", "branch_id": "branch-1"},
        ]
        with self.app.test_request_context(
            "/settings/policy-templates/template-1/deploy",
            method="POST",
            json={"branch_id": "branch-1", "reason": "Baseline rollout", "idempotency_key": "request-1"},
        ):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(settings.db, "get_policy_template", return_value=template), \
                 mock.patch.object(settings.db, "get_branch", return_value=branch), \
                 mock.patch.object(settings.db, "get_endpoints", return_value=fleet), \
                 mock.patch.object(settings.db, "create_policy_deployment", return_value={
                     "deployment_id": "deployment-1", "targeted": 2, "queued": 2,
                 }) as create_deployment, \
                 mock.patch.object(settings.db, "audit") as audit, \
                 mock.patch("services.entitlements.check_job", return_value=SimpleNamespace(allowed=True)):
                response = _undecorated(settings.deploy_policy_template)("template-1")

        data = response.get_json()
        self.assertEqual(data["queued"], 2)
        self.assertEqual(data["targeted"], 2)
        create_deployment.assert_called_once()
        self.assertEqual(create_deployment.call_args.args[-1], "request-1")
        audit.assert_called_once()

    def test_deploy_can_target_specific_agents_within_branch(self):
        template = {
            "id": "template-1", "company_id": "company-1", "name": "Firewall",
            "settings": {"firewall_all_profiles_enabled": True},
        }
        branch = {"id": "branch-1", "company_id": "company-1", "name": "HQ"}
        fleet = [
            {"id": "endpoint-1", "branch_id": "branch-1", "platform": "windows", "tags": ["finance"]},
            {"id": "endpoint-2", "branch_id": "branch-1", "platform": "windows", "tags": ["sales"]},
        ]
        with self.app.test_request_context(
            "/settings/policy-templates/template-1/deploy", method="POST",
            json={
                "branch_id": "branch-1", "include_endpoint_ids": ["endpoint-2"],
                "rollout_percentage": 100, "idempotency_key": "specific-1",
            },
        ):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(settings.db, "get_policy_template", return_value=template), \
                 mock.patch.object(settings.db, "get_branch", return_value=branch), \
                 mock.patch.object(settings.db, "get_endpoints", return_value=fleet), \
                 mock.patch.object(settings.db, "create_policy_deployment", return_value={
                     "deployment_id": "deployment-1", "targeted": 1, "queued": 1,
                 }) as create_deployment, \
                 mock.patch.object(settings.db, "audit"), \
                 mock.patch("services.entitlements.check_job", return_value=SimpleNamespace(allowed=True)):
                response = _undecorated(settings.deploy_policy_template)("template-1")

        self.assertEqual(response.get_json()["queued"], 1)
        self.assertEqual(create_deployment.call_args.kwargs["endpoint_ids"], ["endpoint-2"])
        selector = create_deployment.call_args.kwargs["target_selector"]
        self.assertEqual(selector["include_endpoint_ids"], ["endpoint-2"])

    def test_visual_firewall_policy_saves_as_a_standard_policy_template(self):
        rules = [{
            "name": "ERP egress", "enabled": True, "direction": "out",
            "action": "allow", "protocol": "tcp",
            "program": "C:\\Program Files\\ERP\\erp.exe",
            "remote_addresses": ["10.20.0.0/16"], "remote_ports": ["443"],
            "local_ports": [], "profiles": ["domain", "private"],
        }]
        with self.app.test_request_context(
            "/settings/firewall-policies/save", method="POST",
            json={"name": "ERP Firewall", "description": "ERP access", "rules": rules},
        ):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(settings.db, "create_policy_template", return_value={"id": "template-1"}) as create, \
                 mock.patch.object(settings.db, "audit") as audit:
                response = _undecorated(settings.save_firewall_policy)()
        self.assertTrue(response.get_json()["ok"])
        saved_settings = create.call_args.args[3]
        self.assertTrue(saved_settings["firewall_all_profiles_enabled"])
        self.assertIn("ERP egress", saved_settings["windows_firewall_rules"])
        audit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
