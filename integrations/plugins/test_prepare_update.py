"""Release maintenance regressions; all release inputs are local fixtures."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_update import prepare, commit_request, MANIFESTS, MARKETPLACES
from pin_runtime import PLATFORMS


class UpdatePreparation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in MANIFESTS + MARKETPLACES + ['plugins/skillguard/runtime-lock.json']:
            target = self.root/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/name, target)
        self.checksums = '\n'.join('a'*64+'  skillguard_9.0.0_'+key+'.tar.gz' for key in PLATFORMS)

    def test_bumps_all_versions_together_and_is_idempotent(self):
        self.assertTrue(prepare(self.root, '9.0.0', self.checksums))
        versions = [json.loads((self.root/name).read_text())['version'] for name in MANIFESTS]
        self.assertEqual(len(set(versions)), 1)
        for name in MARKETPLACES:
            data = json.loads((self.root/name).read_text())
            self.assertEqual(next(x['version'] for x in data['plugins'] if x['name']=='skillguard'), versions[0])
        self.assertFalse(prepare(self.root, '9.0.0', self.checksums))

    def test_bad_checksums_or_downgrade_leave_files_unchanged(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        for version, checksums in [('9.0.0',self.checksums.splitlines()[0]),('0.0.1',self.checksums.replace('9.0.0','0.0.1'))]:
            with self.assertRaises((ValueError,KeyError)):
                prepare(self.root, version, checksums)
            self.assertEqual(before, {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_commit_request_contains_only_packaged_files_and_signoff(self):
        request = commit_request(self.root, 'OSSAfrica/skillguard', 'automation/test', 'a'*40, 'v9.0.0')
        data = request['variables']['input']
        self.assertEqual(data['expectedHeadOid'], 'a'*40)
        self.assertIn('Signed-off-by: github-actions[bot]', data['message']['body'])
        paths = {item['path'] for item in data['fileChanges']['additions']}
        self.assertEqual(paths, set(MANIFESTS+MARKETPLACES+['plugins/skillguard/runtime-lock.json']))
        self.assertIn('signature { isValid }', request['query'])
