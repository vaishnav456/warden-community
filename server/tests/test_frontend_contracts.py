import pathlib
import re
import unittest


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES_DIR = SERVER_DIR / "templates"
WARDEN_JS = SERVER_DIR / "static" / "js" / "warden.js"
FORM_UI_JS = SERVER_DIR / "static" / "js" / "form-ui.js"


class FrontendContractTests(unittest.TestCase):
    def _templates(self):
        for path in TEMPLATES_DIR.rglob("*.html"):
            yield path, path.read_text(encoding="utf-8")

    def test_runtime_assets_never_depend_on_a_public_cdn(self):
        remote_asset = re.compile(
            r"<(?:script|link)\b[^>]+(?:src|href)=[\"']https?://",
            re.IGNORECASE,
        )
        for path, source in self._templates():
            self.assertIsNone(remote_asset.search(source), f"Remote asset in {path}")
        css_dir = SERVER_DIR / "static" / "css"
        for path in css_dir.rglob("*.css"):
            source = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotRegex(source, r"(?i)@import\s+url\([\"']?https?://")
            self.assertNotRegex(source, r"(?i)url\([\"']?https?://")
        self.assertTrue((SERVER_DIR / "static" / "vendor" / "alpinejs.min.js").is_file())
        self.assertTrue((SERVER_DIR / "static" / "fonts" / "inter" / "400.css").is_file())

    def test_container_runtime_is_non_root_and_read_only(self):
        server_dockerfile = (SERVER_DIR / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("USER 10001:10001", server_dockerfile)

    def test_security_evidence_and_recovery_automation_are_present(self):
        database = (SERVER_DIR / "db.py").read_text(encoding="utf-8")
        security = (SERVER_DIR / "middleware" / "security.py").read_text(encoding="utf-8")
        self.assertIn("consume_rate_limit", database)
        self.assertIn("verify_audit_chain", database)
        self.assertIn("SECURITY_AUDIT", database)
        self.assertIn("durable_key", security)

    def test_alpine_components_are_csp_registered(self):
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        registered = set(re.findall(r"Alpine\.data\(['\"]([A-Za-z0-9_]+)", javascript))
        referenced = set()
        for path, source in self._templates():
            for value in re.findall(r'\bx-data="([^"]*)"', source):
                if not value:
                    continue
                self.assertFalse(
                    value.lstrip().startswith(("{", "[")),
                    f"{path.name} uses inline Alpine state, which the CSP build cannot evaluate",
                )
                referenced.add(value.split("(", 1)[0].strip())
        self.assertFalse(
            referenced - registered,
            f"Unregistered Alpine components: {sorted(referenced - registered)}",
        )

    def test_periodic_htmx_requests_drop_overlaps(self):
        for path, source in self._templates():
            for tag in re.findall(r"<[^>]+>", source, flags=re.DOTALL):
                if "hx-trigger=" not in tag or "every " not in tag:
                    continue
                self.assertIn(
                    'hx-sync="this:drop"',
                    tag,
                    f"{path.name} has a periodic HTMX request without overlap protection",
                )

    def test_authenticated_shell_renews_only_active_sessions(self):
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        self.assertIn('meta name="session-idle-minutes"', base)
        self.assertIn("startSessionActivityMonitor();", javascript)
        self.assertIn("fetch('/auth/refresh'", javascript)
        self.assertIn("fetch('/auth/logout'", javascript)
        self.assertIn("navigator.locks.request('warden-auth-refresh'", javascript)

    def test_authenticated_shell_has_route_aware_page_documentation(self):
        from jinja2 import Environment, FileSystemLoader
        from services.page_help import page_help_for

        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        partial = (TEMPLATES_DIR / "partials" / "page_help.html").read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertIn('{% include "partials/page_help.html" %}', base)
        self.assertIn("page_help.title", partial)
        self.assertIn("page_help.overview", partial)
        self.assertIn("page_help.sections", partial)
        self.assertIn("page-guide-panel", stylesheet)
        rendered = Environment(loader=FileSystemLoader(TEMPLATES_DIR)).get_template(
            "partials/page_help.html"
        ).render(page_help=page_help_for("/storage"))
        self.assertIn("Warden Home guide", rendered)
        self.assertIn("Recommended workflow", rendered)
        self.assertIn("Register each node", rendered)

    def test_home_node_setup_is_a_single_secure_package(self):
        page = (TEMPLATES_DIR / "home" / "index.html").read_text(encoding="utf-8")
        routes = (SERVER_DIR / "routes" / "home.py").read_text(encoding="utf-8")
        self.assertIn("Download Windows package", page)
        self.assertIn("Download Linux package", page)
        self.assertIn("executable and JSON together", page)
        self.assertIn("bootstrap-package/windows", page)
        self.assertIn("bootstrap-package/linux", page)
        self.assertIn("zipfile.ZipFile", routes)
        self.assertIn("tarfile.open", routes)
        self.assertIn('response.headers["Cache-Control"] = "private, no-store"', routes)

    def test_validation_and_confirmation_ui_is_warden_owned(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        form_ui = FORM_UI_JS.read_text(encoding="utf-8")
        remote = (TEMPLATES_DIR / "endpoints" / "remote_view.html").read_text(encoding="utf-8")
        self.assertIn('id="warden-action-dialog"', base)
        self.assertIn("static/js/form-ui.js", base)
        self.assertIn("warden-field-error", form_ui)
        self.assertIn("window.wardenConfirm", form_ui)
        self.assertIn("window.wardenPrompt", form_ui)
        self.assertNotRegex(WARDEN_JS.read_text(encoding="utf-8"), r"(?:window\.)?\bconfirm\s*\(")
        self.assertNotRegex(WARDEN_JS.read_text(encoding="utf-8"), r"(?:window\.)?\bprompt\s*\(")
        self.assertNotRegex(remote, r"(?:window\.)?\bconfirm\s*\(")

    def test_endpoint_jobs_and_experience_use_operational_components(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        detail += (TEMPLATES_DIR / "partials" / "endpoint_job_history.html").read_text(encoding="utf-8")
        for contract in (
            "endpoint-job-counters", "endpoint-job-actions", "endpoint-job-record",
            "endpoint-job-error", "endpoint-experience-page", "announcement_require_ack",
            "remote-consent-customizer",
        ):
            self.assertIn(contract, detail)
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        self.assertIn("consent_title", javascript)
        self.assertIn("consent_message", javascript)
        self.assertIn("wardenFetchJSON(`/endpoints/${this.endpointId}/experience`", javascript)
        self.assertIn("headers.set('Accept', 'application/json')", javascript)

    def test_every_tenant_page_has_specific_documentation(self):
        from services.page_help import page_help_for

        tenant_pages = (
            "/", "/endpoints", "/topology", "/endpoints/example", "/endpoints/example/remote-view/session",
            "/assets", "/users", "/directory", "/storage", "/apps", "/jobs",
            "/jobs/example", "/escalations", "/escalations/saved", "/alerts",
            "/compliance", "/patches", "/effective-policy", "/network",
            "/vulnerabilities", "/schedule", "/status", "/audit", "/settings",
            "/settings/tokens", "/settings/builds", "/settings/branches",
            "/settings/policy-templates", "/settings/firewall-policies",
            "/settings/integrations", "/settings/thresholds", "/settings/security",
        )
        for path in tenant_pages:
            with self.subTest(path=path):
                guide = page_help_for(path)
                self.assertNotEqual(guide["title"], "Page guide")
                self.assertGreaterEqual(len(guide["sections"]), 3)
                self.assertTrue(all(len(section["items"]) >= 3 for section in guide["sections"]))

    def test_central_directory_is_reachable_from_authenticated_navigation(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        directory = (TEMPLATES_DIR / "directory" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="/directory"', base)
        self.assertIn('action="/directory"', directory)
        self.assertIn("Export CSV", directory)
        self.assertIn("+ Add local user", directory)
        self.assertIn("Assign user to endpoints", directory)
        self.assertIn("Unique credentials for every endpoint", directory)
        self.assertIn("Rotate each selected local account", directory)
        self.assertIn("Delete this account from endpoints removed", directory)
        self.assertIn('name="access"', directory)
        self.assertIn('name="sort"', directory)
        self.assertIn("Login email", directory)
        self.assertIn("wardenLoginEmail", directory)
        self.assertIn("identity.login_email", directory)

    def test_computer_topology_is_live_operational_ui(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        page = (TEMPLATES_DIR / "topology" / "index.html").read_text(encoding="utf-8")
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        icons = (SERVER_DIR / "static" / "warden-icons.svg").read_text(encoding="utf-8")
        self.assertIn('href="/topology"', base)
        self.assertIn('x-data="topologyPage"', page)
        self.assertIn('data-can-edit=', page)
        self.assertIn('interactive_user', page)
        self.assertIn('beginEndpointDrag', javascript)
        self.assertIn('Math.hypot(event.clientX - this.dragStartClientX, event.clientY - this.dragStartClientY)', javascript)
        self.assertIn('if (this.dragMoved) this.updateEndpointDragPosition(event)', javascript)
        self.assertIn('beginCanvasPointer', javascript)
        self.assertIn('roomDraft.width < 3', javascript)
        self.assertIn("setInterval(() => { if (!this.dragEndpointId && !this.replay) this.refresh(true); }, 15000)", javascript)
        self.assertIn('.topology-canvas', stylesheet)
        self.assertIn('.topology-page.is-focus-map', stylesheet)
        self.assertIn('topology-room-draft', page)
        self.assertIn('class="topology-grid" x="-2000" y="-1200"', page)
        self.assertNotIn('topology-floor-boundary', page)
        self.assertIn('Draw room', page)
        self.assertIn('Add asset', page)
        self.assertIn('Describe connection', page)
        self.assertIn('createLink()', javascript)
        self.assertIn("deviceKind(endpoint)", javascript)
        self.assertIn("appendDeviceOutline", javascript)
        self.assertIn("endpointAddressSummary(endpoint)", javascript)
        self.assertIn("endpointAddresses(selectedEndpoint)", page)
        self.assertIn("device-outline is-${kind}", javascript)
        self.assertIn("platform-${endpoint.platform || 'windows'}", javascript)
        self.assertIn("canvasZoom: 1", javascript)
        self.assertIn("zoomCanvas(delta)", javascript)
        self.assertIn("canvasViewBox()", javascript)
        self.assertIn("setAttribute('viewBox', this.canvasViewBox())", javascript)
        self.assertIn('aria-label="Canvas zoom"', page)
        self.assertIn("attachCanvasInteractions()", javascript)
        self.assertIn("{ passive: false }", javascript)
        self.assertNotIn('@wheel.prevent="zoomCanvasWheel($event)"', page)
        self.assertIn("device-hover-card", javascript)
        self.assertIn("showFloorRail: false", javascript)
        self.assertIn("closeInspector()", javascript)
        self.assertIn('@click="closeInspector()"', page)
        self.assertIn('.topology-page.is-floor-rail-hidden', stylesheet)
        self.assertIn('.app-content:has(> .topology-page)', stylesheet)
        self.assertIn("device-status-halo", javascript)
        self.assertIn("device-icon-plate", javascript)
        self.assertIn("floorForm: { building: 'Office'", javascript)
        self.assertNotIn("Customer-specific office", page)
        self.assertIn('.topology-link.is-fiber', stylesheet)
        self.assertIn('.device-outline.is-iot', stylesheet)
        self.assertIn('.topology-device.is-offline .device-outline', stylesheet)
        self.assertIn('.topology-device.is-online.platform-windows', stylesheet)
        self.assertIn('id="topology"', icons)

    def test_directory_photo_inputs_belong_to_their_respective_dialogs(self):
        directory = (TEMPLATES_DIR / "directory" / "index.html").read_text(encoding="utf-8")
        warden_dialog, local_dialog = directory.split(
            '<div x-show="modalOpen" x-cloak class="directory-modal-backdrop"', 1
        )
        self.assertEqual(warden_dialog.count('id="warden-identity-photo"'), 1)
        self.assertNotIn('id="directory-new-photo"', warden_dialog)
        self.assertEqual(local_dialog.count('id="directory-new-photo"'), 1)
        self.assertNotIn('id="warden-identity-photo"', local_dialog)

    def test_all_dialog_families_have_light_surface_overrides(self):
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        for selector in (
            ".slide-panel", ".directory-modal", ".endpoint-dialog",
            ".modal", ".dialog", ".drawer", ".popover", ".dropdown-menu",
            '[class*="fixed inset-0 bg-black"]',
        ):
            self.assertIn(selector, stylesheet)
        self.assertIn("background:rgba(255,255,255,.98)!important", stylesheet)

    def test_policy_benchmarks_can_be_cloned_and_modified(self):
        policy_page = (TEMPLATES_DIR / "settings" / "policy_templates.html").read_text(encoding="utf-8")
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertIn("BENCHMARK STARTERS", policy_page)
        self.assertIn("enforced", policy_page)
        self.assertIn("assessed", policy_page)
        self.assertIn("Reference source", policy_page)
        self.assertIn("benchmark.coverage", policy_page)
        self.assertIn("Use &amp; modify", policy_page)
        self.assertIn("Clone &amp; modify", policy_page)
        self.assertIn("cloneFromElement", javascript)
        self.assertIn("Copy of ${element.dataset.templateName", javascript)
        self.assertIn("this.values[key] === 'true'", javascript)
        self.assertIn('<option value="false">Disabled</option>', policy_page)
        self.assertIn('input[type="file"]::file-selector-button', stylesheet)

    def test_shell_has_responsive_persistent_navigation(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "warden.css").read_text(encoding="utf-8")
        workbench = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertIn('aria-controls="app-sidebar"', base)
        self.assertIn('class="sidebar-nav flex-1 min-h-0 overflow-y-auto', base)
        self.assertIn("#app-sidebar .sidebar-nav", workbench)
        self.assertIn("overflow-y:auto", workbench)
        self.assertIn("toggleNavigation()", base)
        self.assertIn("warden.sidebarCollapsed", javascript)
        self.assertIn("sidebar-mobile-open", stylesheet)
        self.assertIn(".fleet-summary-strip > *", stylesheet)

    def test_endpoint_can_be_removed_without_uninstalling_agent(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        self.assertIn("Remove from Warden", detail)
        self.assertIn("Remove and free license", detail)
        self.assertIn("remove-from-warden", javascript)

    def test_endpoint_secure_update_is_exposed_with_rollback_copy(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        self.assertIn("REINSTALL_AGENT", detail)
        self.assertIn("REINSTALL_AGENT", javascript)
        self.assertIn("automatically roll back", javascript)

    def test_endpoint_workspace_renders_every_advertised_component(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        expected_tabs = {
            "overview", "events", "jobs", "sessions", "software", "users",
            "alerts", "compliance", "policy", "metrics",
        }
        linked_tabs = set(re.findall(r"\('([a-z]+)','[^']+'", detail))
        rendered_tabs = {"overview"} | set(re.findall(r"tab == '([a-z]+)'", detail))
        self.assertTrue(expected_tabs.issubset(linked_tabs))
        self.assertTrue(expected_tabs.issubset(rendered_tabs))
        self.assertIn("endpoint-section-link", detail)
        self.assertIn("warden-icons.svg", detail)
        self.assertIn("endpoint-modal-backdrop", detail)
        self.assertIn("showRemoteModal", detail)
        self.assertIn("showCreateUserModal", detail)
        self.assertIn("showRemoveEndpointModal", detail)
        self.assertIn("showJobModal", detail)

    def test_remote_endpoint_view_keeps_screen_dark_and_controls_light(self):
        remote = (TEMPLATES_DIR / "endpoints" / "remote_view.html").read_text(encoding="utf-8")
        self.assertIn("background: #0b1018", remote)
        self.assertIn("background: rgba(255,255,255,.94)", remote)
        self.assertIn("#remote", remote)
        for control in ("btn-clipboard", "btn-keyboard", "btn-timeline", "btn-processes", "btn-upload", "btn-download", "btn-disconnect"):
            self.assertIn(f'id="{control}"', remote)

    def test_remote_tools_stay_inside_the_remote_workspace(self):
        remote = (TEMPLATES_DIR / "endpoints" / "remote_view.html").read_text(encoding="utf-8")
        workspace = remote.index('<div id="remote-wrap">')
        keyboard = remote.index('<aside id="keyboard-panel"')
        workspace_close = remote.index("\n</div>\n\n<script", keyboard)
        self.assertLess(workspace, keyboard)
        self.assertLess(keyboard, workspace_close)

    def test_saved_remote_notes_are_visible_in_session_history(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        endpoint_routes = (SERVER_DIR / "routes" / "endpoints.py").read_text(encoding="utf-8")
        self.assertIn("Notes &amp; chat", detail)
        self.assertIn("session-transcript", detail)
        self.assertIn('session["collaboration_events"]', endpoint_routes)

    def test_ctrl_alt_delete_uses_secure_attention_operation(self):
        remote = (TEMPLATES_DIR / "endpoints" / "remote_view.html").read_text(encoding="utf-8")
        self.assertIn("send({ type: 'ctrl_alt_del' })", remote)
        self.assertNotIn("send({ type: 'keydown', key: 'Delete' })", remote)

    def test_remote_helper_restart_keeps_last_valid_frame(self):
        remote = (TEMPLATES_DIR / "endpoints" / "remote_view.html").read_text(encoding="utf-8")
        self.assertIn("if (canvas.width !== sw || canvas.height !== sh)", remote)
        self.assertNotIn("canvas.width = sw; canvas.height = sh;", remote)

    def test_vm_ssh_bootstrap_is_not_publicly_shipped(self):
        app_source = (SERVER_DIR / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("/vm-access-bootstrap", app_source)
        self.assertNotIn("/vm-build-bootstrap", app_source)
        self.assertFalse((SERVER_DIR / "static" / "setup-warden-vm-ssh.ps1").exists())
        self.assertFalse((SERVER_DIR / "static" / "setup-warden-build-vm.ps1").exists())

    def test_endpoint_firewall_menu_uses_a_real_sprite_icon(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        sprites = (SERVER_DIR / "static" / "warden-icons.svg").read_text(encoding="utf-8")
        self.assertIn("('firewall','Firewall','SECURITY','PUSH_LOCAL_POLICY','firewall')", detail)
        self.assertIn('<symbol id="firewall"', sprites)
        self.assertIn('#firewall"></use></svg>Create custom rules', detail)

    def test_endpoint_packet_capture_is_bounded_and_discoverable(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        self.assertIn("Capture packets", detail)
        self.assertIn("Download PCAPNG", detail)
        self.assertIn('min="5" max="120"', detail)
        self.assertIn('min="1" max="8"', detail)
        self.assertIn("Packet contents may contain sensitive tenant data", detail)
        self.assertIn("CAPTURE_PACKETS", javascript)

    def test_endpoint_platforms_have_distinct_visual_marks(self):
        sprites = (SERVER_DIR / "static" / "warden-icons.svg").read_text(encoding="utf-8")
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        endpoint_row = (TEMPLATES_DIR / "partials" / "endpoint_row.html").read_text(encoding="utf-8")
        dashboard = (TEMPLATES_DIR / "dashboard.html").read_text(encoding="utf-8")
        for platform in ("windows", "macos", "linux"):
            self.assertIn(f'id="platform-{platform}"', sprites)
        self.assertIn("#platform-", detail)
        self.assertIn("#platform-", endpoint_row)
        self.assertIn("#platform-", dashboard)

    def test_endpoint_navigation_has_no_legacy_dark_border(self):
        detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertIn("Refresh device info", detail)
        self.assertIn(".endpoint-section-nav { padding:.7rem; border:0; border-right:1px solid #e8ecf2;", stylesheet)
        self.assertIn("color:#667085; border:0; border-radius:11px", stylesheet)

    def test_mfa_setup_qr_is_centered(self):
        setup = (TEMPLATES_DIR / "settings" / "mfa_setup.html").read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertIn('class="max-w-md mx-auto"', setup)
        self.assertIn('class="mfa-qr-frame"', setup)
        self.assertIn(".mfa-qr-frame { width:100%; display:flex; align-items:center; justify-content:center; }", stylesheet)

    def test_disabled_buttons_do_not_impersonate_loading_state(self):
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertNotIn(".btn[disabled]::after", stylesheet)
        self.assertIn(".btn.is-loading::after", stylesheet)
        self.assertIn(".btn[disabled] { opacity:.52; cursor:not-allowed;", stylesheet)

    def test_shell_has_keyboard_navigation_launcher(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        javascript = WARDEN_JS.read_text(encoding="utf-8")
        self.assertIn("@keydown.ctrl.k.window.prevent", base)
        self.assertIn("Find a page or workflow", base)
        self.assertIn("openFirstCommandResult", javascript)

    def test_light_mobile_design_system_is_loaded_across_auth_surfaces(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        login = (TEMPLATES_DIR / "login.html").read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        login_script = (SERVER_DIR / "static" / "js" / "login.js").read_text(encoding="utf-8")
        self.assertIn("css/workbench.css", base)
        self.assertIn("css/workbench.css", login)
        self.assertIn('class="mobile-tab-bar"', base)
        self.assertIn('id="route-progress"', base)
        self.assertIn("color-scheme: light", stylesheet)
        self.assertIn("prefers-reduced-motion:reduce", stylesheet)
        self.assertIn("tap-ripple", stylesheet)
        self.assertIn("is-loading", login_script)

    def test_original_warden_identity_is_used_for_app_login_and_favicon(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        login = (TEMPLATES_DIR / "login.html").read_text(encoding="utf-8")
        favicon = (SERVER_DIR / "static" / "favicon.svg").read_text(encoding="utf-8")
        shield_path = "M20 2.8 34 8.7v10.8c0 8.8-5.3 14.1-14 17.7-8.7-3.6-14-8.9-14-17.7V8.7Z"
        self.assertIn(shield_path, base)
        self.assertIn(shield_path, login)
        self.assertIn("linearGradient", favicon)
        self.assertIn("favicon.svg') }}?v={{ asset_v }}", base)
        self.assertIn("favicon.svg') }}?v={{ asset_v }}", login)

    def test_legacy_favicon_probe_uses_the_canonical_mark(self):
        app_source = (SERVER_DIR / "app.py").read_text(encoding="utf-8")
        self.assertIn('@app.route("/favicon.ico")', app_source)
        self.assertIn('url_for("static", filename="favicon.svg")', app_source)

    def test_existing_agent_reconnect_uses_msi_in_place(self):
        tokens = (TEMPLATES_DIR / "settings" / "tokens.html").read_text(encoding="utf-8")
        self.assertIn("run the MSI as Administrator", tokens)
        self.assertIn("does not install a second agent", tokens)

    def test_zero_touch_enrollment_profiles_are_manageable(self):
        tokens = (TEMPLATES_DIR / "settings" / "tokens.html").read_text(encoding="utf-8")
        stylesheet = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertIn("Create enrollment profile", tokens)
        self.assertIn('name="require_pre_registration"', tokens)
        self.assertIn('name="reclaim_existing"', tokens)
        self.assertIn("Pre-register hardware UUIDs", tokens)
        self.assertIn('name="profile_id"', tokens)
        self.assertIn('name="policy_template_id"', tokens)
        self.assertIn('name="required_app_ids"', tokens)
        self.assertIn('name="install_updates"', tokens)
        self.assertIn('class="enrollment-steps"', tokens)
        self.assertIn('id="enrollment-installer"', tokens)
        self.assertIn('id="enrollment-deployments"', tokens)
        self.assertIn(".enrollment-profile-grid", stylesheet)
        self.assertIn("@media (max-width:760px)", stylesheet)

    def test_patch_asset_and_self_service_surfaces_are_reachable(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        patches = (TEMPLATES_DIR / "patches" / "index.html").read_text(encoding="utf-8")
        assets = (TEMPLATES_DIR / "assets" / "index.html").read_text(encoding="utf-8")
        apps = (TEMPLATES_DIR / "apps" / "library.html").read_text(encoding="utf-8")
        self.assertIn('href="/patches"', base)
        self.assertIn('href="/assets"', base)
        self.assertIn("Install pending", patches)
        self.assertIn("Applicable update inventory", patches)
        self.assertIn("Warranty", assets)
        self.assertIn('name="self_service"', apps)

    def test_firewall_policy_editor_is_visual_and_gpo_style(self):
        templates = (TEMPLATES_DIR / "settings" / "policy_templates.html").read_text(encoding="utf-8")
        firewall = (TEMPLATES_DIR / "settings" / "firewall_policies.html").read_text(encoding="utf-8")
        navigation = (TEMPLATES_DIR / "settings" / "_navigation.html").read_text(encoding="utf-8")
        script = WARDEN_JS.read_text(encoding="utf-8")
        self.assertIn("Open firewall editor", templates)
        self.assertIn("Firewall Policies", navigation)
        self.assertIn("Executable path", firewall)
        self.assertIn("Choose an installed application", firewall)
        self.assertIn("enter/edit its absolute path", firewall)
        self.assertIn("Remote IP addresses or CIDR", firewall)
        self.assertIn("Local ports", firewall)
        self.assertIn("Remote ports", firewall)
        self.assertIn("Rollout ring", firewall)
        self.assertIn("Entire branch", firewall)
        self.assertIn("Endpoint group / tag", firewall)
        self.assertIn("Specific agents", firewall)
        self.assertIn("Deployment preview", firewall)
        self.assertIn("Clone", firewall)
        endpoint = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        self.assertIn("Firewall policy on this agent", endpoint)
        self.assertIn("Create custom rules", endpoint)
        self.assertIn("Custom endpoint firewall policy", endpoint)
        self.assertIn("applyCustomEndpointFirewallPolicy", script)
        self.assertIn("Assign saved policy to this agent", endpoint)
        self.assertIn("Choose from this endpoint’s application inventory", endpoint)
        self.assertIn("enter a custom absolute path", endpoint)
        self.assertIn("endpointFirewallApplications", script)

    def test_warden_only_enrollment_is_visible_and_enabled_by_default(self):
        tokens = (TEMPLATES_DIR / "settings" / "tokens.html").read_text(encoding="utf-8")
        self.assertIn('name="warden_only_mode" value="1" x-model="wardenOnly" checked', tokens)
        self.assertIn('x-data="enrollmentProfileForm"', tokens)
        self.assertIn('name="recovery_admin_username"', tokens)
        self.assertIn('name="recovery_admin_password"', tokens)
        self.assertIn("never locks the device before both approved accounts are usable", tokens)

    def test_tenant_can_manage_encrypted_microsoft_credentials(self):
        integrations = (TEMPLATES_DIR / "settings" / "integrations.html").read_text(encoding="utf-8")
        self.assertIn("Directory (tenant) ID", integrations)
        self.assertIn("Application (client) ID", integrations)
        self.assertIn("Client secret value", integrations)
        self.assertIn("Organization.Read.All", integrations)
        self.assertIn("DeviceManagementServiceConfig.Read.All", integrations)
        self.assertIn("Save and test connection", integrations)
        self.assertIn("Sync Autopilot devices", integrations)
        self.assertNotIn('value="{{ saved_config.get(\'client_secret\'', integrations)

    def test_linux_and_macos_surfaces_are_marked_alpha(self):
        endpoint_list = (TEMPLATES_DIR / "endpoints" / "list.html").read_text(encoding="utf-8")
        endpoint_detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        tokens = (TEMPLATES_DIR / "settings" / "tokens.html").read_text(encoding="utf-8")
        self.assertIn("Linux Intel / AMD 64-bit — Alpha", endpoint_list)
        self.assertIn("macOS Apple silicon — Alpha", endpoint_list)
        self.assertIn("badge-alpha", endpoint_detail)
        self.assertIn("Linux · x64 — Alpha", tokens)
        self.assertIn("macOS · Apple silicon — Alpha", tokens)

    def test_app_library_formats_match_shipping_agents(self):
        apps = (TEMPLATES_DIR / "apps" / "library.html").read_text(encoding="utf-8")
        endpoint = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        self.assertIn('accept=".exe,.msi,.deb,.rpm,.pkg"', apps)
        self.assertNotIn("'msix'", endpoint)

    def test_admin_reset_password_is_shown_once(self):
        users = (TEMPLATES_DIR / "users" / "list.html").read_text(encoding="utf-8")
        script = (SERVER_DIR / "static" / "js" / "warden.js").read_text(encoding="utf-8")
        self.assertIn("Save this password now", users)
        self.assertIn("resetPasswordValue = data.new_password", script)
        self.assertIn("resetPasswordValue: ''", script)
        self.assertIn("showEdit: false", script)

    def test_tls_pin_rotation_has_tenant_ui(self):
        security = (TEMPLATES_DIR / "settings" / "security.html").read_text(encoding="utf-8")
        self.assertIn("Agent TLS Trust Rotation", security)
        self.assertIn("fingerprints", security)

    def test_device_experience_bulk_and_jobs_are_live(self):
        endpoint_list = (TEMPLATES_DIR / "endpoints" / "list.html").read_text(encoding="utf-8")
        endpoint_detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        jobs = (TEMPLATES_DIR / "jobs" / "list.html").read_text(encoding="utf-8")
        self.assertIn('value="APPLY_DEVICE_EXPERIENCE"', endpoint_list)
        self.assertIn("available to offline endpoints for 72 hours", endpoint_list)
        self.assertIn('/endpoints/experience/bulk', WARDEN_JS.read_text(encoding="utf-8"))
        self.assertIn('hx-trigger="every 5s, refresh"', endpoint_detail)
        self.assertIn('/partials/jobs-table', jobs)

    def test_ad_laps_policy_is_explained_for_warden_only_devices(self):
        endpoint_detail = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        from policy_settings import POLICY_SETTINGS
        # The public source tree intentionally does not redistribute Microsoft's
        # ADMX/ADML-derived catalog. Operators may generate it from policy files
        # licensed on their own Windows systems; when present, the LAPS setting
        # must retain its Active Directory requirement marker.
        laps = POLICY_SETTINGS.get("laps_adpasswordencryptionenabled")
        if laps is not None:
            self.assertTrue(laps["requires_ad"])
        policy_source = (SERVER_DIR / "policy_settings.py").read_text(encoding="utf-8")
        self.assertIn('"laps_adpasswordencryptionenabled"', policy_source)
        self.assertIn('meta["requires_ad"] = True', policy_source)
        self.assertIn("Requires Active Directory password backup", endpoint_detail)
        self.assertIn("Warden-only credentials use separate encryption", endpoint_detail)

    def test_operator_branding_is_configuration_driven(self):
        base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
        login = (TEMPLATES_DIR / "login.html").read_text(encoding="utf-8")
        env_example = (SERVER_DIR / ".env.example").read_text(encoding="utf-8")
        self.assertIn("{{ brand_name | upper }}", base)
        self.assertIn("{{ brand_tagline }}", login)
        self.assertIn("BRAND_NAME=Warden", env_example)
        self.assertIn("BRAND_LOGO_PATH=/static/", env_example)

    def test_endpoint_software_shows_vulnerability_exposure_and_actions_fit(self):
        endpoint = (TEMPLATES_DIR / "endpoints" / "detail.html").read_text(encoding="utf-8")
        vulnerabilities = (TEMPLATES_DIR / "security" / "vulnerabilities.html").read_text(encoding="utf-8")
        css = (SERVER_DIR / "static" / "css" / "workbench.css").read_text(encoding="utf-8")
        self.assertIn("Vulnerability exposure", endpoint)
        self.assertIn("Known exploited", endpoint)
        self.assertIn("return_to_endpoint", endpoint)
        self.assertIn("vulnerability-status-form", vulnerabilities)
        self.assertIn("grid-template-columns:minmax(10rem,1fr) auto", css)

    def test_remote_special_keys_stay_inside_their_panel(self):
        remote = (TEMPLATES_DIR / "endpoints" / "remote_view.html").read_text(encoding="utf-8")
        self.assertIn("repeat(auto-fit,minmax(4.4rem,1fr))", remote)
        self.assertIn("max-height:calc(100dvh - 4.8rem)", remote)

    def test_endpoint_jobs_show_approval_state_instead_of_silent_queueing(self):
        history = (TEMPLATES_DIR / "partials" / "endpoint_job_history.html").read_text(encoding="utf-8")
        script = WARDEN_JS.read_text(encoding="utf-8")
        self.assertIn("Awaiting approval", history)
        self.assertIn("The Agent has not received this operation", history)
        self.assertIn("awaiting administrator approval", script)


if __name__ == "__main__":
    unittest.main()
