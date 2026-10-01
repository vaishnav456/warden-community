import pathlib
import unittest

from jinja2 import Environment, FileSystemLoader

SERVER = pathlib.Path(__file__).resolve().parents[1]


class WorkspaceUITests(unittest.TestCase):
    def test_workspace_loads_shared_components_after_legacy_styles(self):
        base = (SERVER / "templates/base.html").read_text(encoding="utf-8")
        self.assertGreater(base.index("css/workspace-ui.css"), base.index("css/workbench.css"))
        css = (SERVER / "static/css/workspace-ui.css").read_text(encoding="utf-8")
        self.assertIn("@import url('./design-tokens.css');", css)
        self.assertIn(".console-card,.console-metrics article,.metric-card", css)
        self.assertIn("background:var(--accent-500)!important", css)
        self.assertIn("@media(max-width:650px)", css)
        self.assertIn("grid-template-columns:repeat(2,minmax(0,1fr))", css)
        self.assertNotIn("overflow-x:hidden", css)

    def test_dashboard_metric_remains_a_real_link_and_shows_total(self):
        environment = Environment(loader=FileSystemLoader(str(SERVER / "templates")), autoescape=True)
        html = environment.get_template("partials/dashboard_stats.html").render(
            online_count=2, offline_count=1, total_count=3,
            pending_escalations=0, open_alerts=1, asset_v="test",
        )
        self.assertIn("of 3 managed", html)
        self.assertIn('href="/endpoints?state=online"', html)
        self.assertIn('href="/alerts"', html)
        source = (SERVER / "routes/dashboard.py").read_text(encoding="utf-8")
        self.assertIn("total_count=len(endpoints)", source)

    def test_dashboard_preserves_live_identity_and_refresh_controls(self):
        source = (SERVER / "templates/dashboard.html").read_text(encoding="utf-8")
        self.assertIn("e.display_name or e.hostname", source)
        self.assertIn("{{ e.hostname }} ·", source)
        self.assertIn('hx-get="/partials/stats"', source)
        self.assertIn("every 30s", source)
        self.assertIn('href="/endpoints/{{ e.id }}"', source)

    def test_shared_styling_does_not_add_a_community_landing_page(self):
        landing = SERVER / "templates/landing.html"
        if landing.exists():
            source = landing.read_text(encoding="utf-8")
            self.assertIn("css/workspace-ui.css", source)
            css = (SERVER / "static/css/landing-console.css").read_text(encoding="utf-8")
            self.assertIn("height:720px", css)
            self.assertIn("height:680px", css)
        else:
            self.assertFalse((SERVER / "routes/marketing.py").exists())
            self.assertFalse((SERVER / "static/js/landing-console.js").exists())
