"""Native plugin bootstrap integrity contracts; no network or agent needed."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_runtime', ROOT / 'plugins/skillguard/runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tar:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            info.linkname = '/untrusted' if kind == tarfile.SYMTYPE else ''
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


class RuntimeContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.binary = b'synthetic binary, never executed'
        self.data = archive([('skillguard', self.binary, tarfile.REGTYPE)])
        self.selected = {'platform':'linux_amd64', 'asset':'fixture.tar.gz', 'sha256':hashlib.sha256(self.data).hexdigest(), 'binary':'skillguard'}
        self.lock = {'version':'0.13.0'}

    def test_validated_archive_does_not_allow_a_receipt_to_bless_changed_binary(self):
        (self.base / 'fixture.tar.gz').write_bytes(self.data)
        (self.base / 'skillguard').write_bytes(self.binary)
        self.assertEqual(runtime.installed(self.base, self.selected), self.base / 'skillguard')
        (self.base / 'skillguard').write_bytes(b'changed')
        (self.base / 'receipt.json').write_text(json.dumps({'sha256':hashlib.sha256(b'changed').hexdigest()}))
        with self.assertRaises(runtime.Unavailable):
            runtime.installed(self.base, self.selected)

    def test_corrupt_traversal_link_and_duplicate_archives_are_rejected(self):
        with self.assertRaises(runtime.Unavailable):
            runtime.payload(self.data + b'changed', self.selected)
        for entries in [[('../escape', b'bad', tarfile.REGTYPE)], [('skillguard', b'', tarfile.SYMTYPE)], [('skillguard', b'one', tarfile.REGTYPE), ('skillguard', b'two', tarfile.REGTYPE)]]:
            data = archive(entries)
            selected = dict(self.selected, sha256=hashlib.sha256(data).hexdigest())
            with self.assertRaises(runtime.Unavailable):
                runtime.payload(data, selected)
        self.assertFalse((self.base.parent / 'escape').exists())

    def test_rejected_download_preserves_previous_installation(self):
        directory = self.base / 'cache'
        directory.mkdir()
        original = directory / 'skillguard'
        original.write_bytes(self.binary)
        with patch.object(runtime, 'selection', return_value=(self.lock, self.selected)), patch.object(runtime, 'location', return_value=directory), patch.object(runtime, 'download', return_value=b'bad'), patch('sys.argv', ['runtime.py','setup']), patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(runtime.main(), 2)
        self.assertEqual(original.read_bytes(), self.binary)

    def test_status_and_mcp_startup_never_download(self):
        for operation in ['status', 'mcp']:
            with patch.object(runtime, 'selection', return_value=(self.lock, self.selected)), patch.object(runtime, 'location', return_value=self.base), patch.object(runtime, 'download') as download, patch('sys.argv', ['runtime.py',operation]), patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO):
                self.assertEqual(runtime.main(), 2)
                download.assert_not_called()

    def test_new_version_cannot_reuse_the_old_cache_or_download_implicitly(self):
        old = runtime.location(str(self.base), self.lock, self.selected)
        old.mkdir(parents=True)
        (old / 'fixture.tar.gz').write_bytes(self.data)
        (old / 'skillguard').write_bytes(self.binary)
        new_lock = dict(self.lock, version='0.14.0')
        with patch.object(runtime, 'selection', return_value=(new_lock, self.selected)), patch.object(runtime, 'download') as download, patch('sys.argv', ['runtime.py','status','--cache-dir',str(self.base)]), patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(runtime.main(), 2)
            download.assert_not_called()
        self.assertEqual(runtime.installed(old,self.selected), old / 'skillguard')

    def test_workspace_cache_and_symlink_binary_are_rejected(self):
        with self.assertRaises(runtime.Unavailable):
            runtime.location(str(Path.cwd() / 'malicious-cache'), self.lock, self.selected)
        if os.name == 'posix':
            outside = self.base / 'outside'
            outside.write_bytes(self.binary)
            (self.base / 'skillguard').symlink_to(outside)
            (self.base / 'fixture.tar.gz').write_bytes(self.data)
            with self.assertRaises(OSError):
                runtime.installed(self.base, self.selected)

    def test_status_reports_advisory_even_when_runtime_is_healthy(self):
        with patch.object(runtime, 'health'):
            result = runtime.status(self.base / 'binary', self.lock)
        self.assertTrue(result['scan_available'])
        self.assertEqual(result['enforcement'], 'advisory')
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['install_tool_available'])
        self.assertEqual(result['hook_state'], 'not_installed')

    def test_redirects_cannot_downgrade_https_or_change_to_an_untrusted_host(self):
        handler = runtime.HTTPSRedirects()
        for target in ['http://github.com/archive', 'https://attacker.invalid/archive', 'file:///tmp/archive']:
            with self.assertRaises(runtime.Unavailable):
                handler.redirect_request(None,None,302,'',{},target)

    def test_all_platform_pins_and_manifests_agree(self):
        plugin = ROOT / 'plugins/skillguard'
        lock = json.loads((plugin / 'runtime-lock.json').read_text())
        self.assertEqual(len(lock['platforms']), 6)
        for key, item in lock['platforms'].items():
            self.assertEqual(item['platform'],key)
            self.assertRegex(item['sha256'], r'^[a-f0-9]{64}$')
            self.assertEqual(item['asset'], 'skillguard_' + lock['version'] + '_' + key + '.tar.gz')
        manifests = [json.loads((plugin / path).read_text()) for path in ['plugin.json','.claude-plugin/plugin.json','.codex-plugin/plugin.json','package.json']]
        self.assertEqual(len({m['version'] for m in manifests}),1)
        for manifest in manifests[:3]:
            self.assertEqual(manifest['name'],'skillguard')
        self.assertFalse((plugin / 'hooks').exists())


if __name__ == '__main__':
    unittest.main()
