import pathlib
import re
import unittest
from jinja2 import Environment, FileSystemLoader

SERVER = pathlib.Path(__file__).resolve().parents[1]


class LandingRedesignTests(unittest.TestCase):
    def render_page(self, trial_enabled):
        environment = Environment(loader=FileSystemLoader(str(SERVER / "templates")), autoescape=True)
        return environment.get_template("landing.html").render(
            url_for=lambda endpoint, filename: "/static/" + filename,
            canonical_url="https://warden.example/",
            console_url="/dashboard", current_user=None, asset_v="test",
            trial_enabled=trial_enabled, trial_url="/trial",
            github_url="https://github.com/vaishnav456/warden-community",
        )

    def test_brand_tokens_are_shared_without_changing_app_palette(self):
        tokens = (SERVER / "static/css/design-tokens.css").read_text()
        workbench = (SERVER / "static/css/workbench.css").read_text()
        page = self.render_page(False)
        self.assertIn("@import url('./design-tokens.css');", workbench)
        self.assertIn("/static/css/design-tokens.css", page)
        self.assertRegex(tokens, r"--accent-500:\s*#0a7aff")
        self.assertRegex(tokens, r"--base-900:\s*#f5f7fb")
        css = (SERVER / "static/css/landing.css").read_text()
        self.assertIn("var(--accent-500)", css)
        self.assertNotIn("--cyan", css)

    def test_rendered_previews_resolve_local_assets_and_icons(self):
        page = self.render_page(True)
        sprites = (SERVER / "static/warden-icons.svg").read_text()
        for filename in re.findall(r'(?:href|src)="/static/([^"?#]+)', page):
            self.assertTrue((SERVER / "static" / filename).is_file(), filename)
        for symbol in re.findall(r'warden-icons.svg[^"]*#([^"]+)', page):
            self.assertIn('id="' + symbol + '"', sprites)
        self.assertNotIn("Warden dashboard · Product preview with sample data", page)
        self.assertIn('aria-label="Warden dashboard preview with sample data"', page)
        self.assertIn("Example job result, not live customer data", page)
        self.assertNotRegex(page, r'\bstyle=')

    def test_trial_ctas_follow_server_configuration(self):
        enabled = self.render_page(True)
        disabled = self.render_page(False)
        self.assertIn("14 days · 10 endpoints · No card required", enabled)
        self.assertIn("deleted at expiry unless you upgrade", enabled)
        self.assertNotIn("Start free trial", disabled)
        self.assertNotIn("14 days", disabled)
        self.assertIn("Explore Community", disabled)

    def test_tabs_have_matching_accessible_panels_without_autoplay(self):
        page = self.render_page(False)
        for key in ("policy", "topology", "remote", "storage", "security"):
            self.assertIn('aria-controls="panel-' + key + '"', page)
            self.assertIn('aria-labelledby="tab-' + key + '"', page)
        javascript = (SERVER / "static/js/landing.js").read_text()
        self.assertIn("panel.hidden = !selected", javascript)
        self.assertIn("'Escape'", javascript)
        self.assertIn("'Home', 'End'", javascript)
        self.assertNotIn("setInterval", javascript)
        css = (SERVER / "static/css/landing.css").read_text()
        self.assertIn("@media(max-width:380px)", css)
        self.assertNotIn("min-width:760px", css)
        self.assertNotIn("overflow-x:hidden", css)

    def test_home_and_firewall_explain_real_security_boundaries(self):
        page = self.render_page(False)
        for text in (
            "No synchronized file contents in the Warden database",
            "Home control metadata is not all encrypted",
            "Warden processes it transiently",
            "not every filename or metadata field",
            "already-downloaded local copies are not automatically erased",
            "Ed25519-signed grant", "normally valid for 15 minutes",
            "AES-256-GCM authenticated chunks",
            "field-level encryption", "not encryption of every database column",
            "Warden Managed:", "Existing Windows, domain and third-party rules",
            "rejects broad outbound block rules",
        ):
            self.assertIn(text, page)
        self.assertIn('data-route-choice="relay"', page)
        self.assertIn('data-firewall-view="outbound"', page)
        self.assertIn('aria-label="Pause page animations"', page)
        self.assertIn("BitLocker", page)
        self.assertIn("escrow recovery passwords", page)
        self.assertNotIn("Names that make sense", page)
        self.assertNotIn("Work you can follow", page)
        javascript = (SERVER / "static/js/landing.js").read_text()
        self.assertIn("motionPreference.addEventListener('change'", javascript)
        self.assertIn("motion.disabled = motionPreference.matches", javascript)
        self.assertNotRegex(javascript, r"\.style\b|setAttribute\(['\"]style")
