import pathlib
import unittest

from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader


class HomeWorkspaceLayoutTests(unittest.TestCase):
    def render(self, section="overview", **updates):
        root = pathlib.Path(__file__).resolve().parents[1]
        environment = Environment(loader=ChoiceLoader([
            DictLoader({"base.html": "{% block extra_head %}{% endblock %}{% block content %}{% endblock %}"}),
            FileSystemLoader(root / "templates"),
        ]), autoescape=True)
        environment.filters["timeago"] = lambda value: value
        values = dict(home_section=section, transfers=[], last_completed=None,
                      spaces=[{"id": "space-a", "name": "Documents", "space_type": "home", "sync_mode": "two_way"}],
                      nodes=[{"id": "node-a", "name": "Office node", "status": "online", "deployment_mode": "p2p"}],
                      assignments=[], endpoints=[], branches=[], identities=[],
                      bootstrap_token=None, g={"admin": {"role": "company_admin"}},
                      csrf_token=lambda: "csrf-test", url_for=lambda *a, **kw: "/static/css/home.css")
        values.update(updates)
        return environment.get_template("home/index.html").render(**values)

    def test_main_actions_precede_overview_and_long_guidance_is_separate(self):
        html = self.render()
        self.assertLess(html.index('class="home-quick-actions"'), html.index('class="home-metrics"'))
        for name in ("Add storage node", "Create space", "Assign access", "Sync now", "Download updates"):
            self.assertIn(name, html)
        self.assertNotIn("Which deployment mode should I use?", html)
        self.assertNotIn('action="/storage/nodes"', html)
        self.assertEqual(html.count('aria-current="page"'), 1)

    def test_node_and_space_panels_keep_post_fields_and_csrf(self):
        for section, action, fields in (
            ("nodes", "/storage/nodes", ("name", "deployment_mode", "local_url", "public_url", "storage_cluster_id")),
            ("spaces", "/storage/spaces", ("name", "space_type", "source", "target", "primary_node_id", "quota_gb", "conflict_policy", "replica_node_ids")),
        ):
            html = self.render(section)
            self.assertIn(f'action="{action}"', html)
            self.assertIn('value="csrf-test"', html)
            for field in fields:
                self.assertIn(f'name="{field}"', html)
            self.assertIn('class="home-advanced"', html)

    def test_access_activity_and_setup_are_independent_sections(self):
        access = self.render("access")
        self.assertIn('action="/storage/assignments"', access)
        self.assertIn("Spaces and assignments", access)
        activity = self.render("activity")
        self.assertIn('action="/storage/spaces/space-a/sync"', activity)
        self.assertIn('href="/storage?section=activity#home-transfers"', activity)
        setup = self.render("setup")
        self.assertIn("Which deployment mode should I use?", setup)
        self.assertIn('href="/storage/download/windows"', setup)
        self.assertNotIn(' p-4" open>', setup)

    def test_one_time_credentials_remain_visible_on_every_section(self):
        bootstrap = {"node": {"id": "node-a"}, "key": "test-only-recovery-key", "recovery": True}
        for section in ("overview", "nodes", "spaces", "access", "activity", "setup"):
            html = self.render(section, bootstrap_token=bootstrap, server_public_key="test-public-key")
            self.assertIn("test-only-recovery-key", html)

    def test_branch_admin_has_no_write_shortcuts(self):
        html = self.render(g={"admin": {"role": "branch_admin"}})
        self.assertIn("View sync results", html)
        self.assertNotIn("Create space</a>", html)


if __name__ == "__main__":
    unittest.main()
