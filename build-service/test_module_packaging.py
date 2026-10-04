"""Core build flags and version contracts without dispatching endpoint jobs."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_notice_packaging as packaging


class ModuleBuildTests(packaging.PackagingTests):
    def test_core_version_and_build_tag_are_selected_together(self):
        source = self.root/'source'
        source.mkdir()
        (source/'config.go').write_text('package main')
        (source/'version_legacy_windows.go').write_text('const agentVersion = "2.6.58"')
        (source/'version_core_windows.go').write_text('const agentVersion = "2.7.0"')
        cfg = self.builder.config
        cfg.AGENT_GO_SOURCE_DIR = source
        cfg.AGENT_POSIX_SOURCE_DIR = source
        cfg.GO_BINARY = 'go'
        cfg.REQUIRE_AUTHENTICODE_UPDATES = False
        for core in (False, True):
            request = dict(id='fixture', target_platform='windows-amd64',
                config_json=dict(agent_core_modules=core, server_url='https://fixture.example',
                                 server_ed25519_pubkey='fixture-public-key', tls_trust_mode='webpki'))
            def build(command, **kwargs):
                self.assertEqual('-tags' in command, core)
                if core: self.assertEqual(command[command.index('-tags')+1], 'warden_core')
                Path(command[command.index('-o')+1]).write_bytes(b'not executable')
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            with patch.object(self.builder.subprocess, 'run', side_effect=build):
                self.builder.run_go_build(request, self.root)
            self.assertEqual(self.builder.read_agent_version(request), '2.7.0' if core else '2.6.58')

    def test_core_zip_excludes_optional_helpdesk_application(self):
        (self.root/'warden-helpdesk.exe').write_bytes(b'optional fixture; must not ship')
        self.request['config_json'] = dict(agent_core_modules=True)
        artifact = self.builder.package_zip(self.request, self.exe, self.cfg, self.provider)
        import zipfile
        with zipfile.ZipFile(artifact) as archive:
            self.assertFalse(any('helpdesk' in name.casefold() for name in archive.namelist()))
