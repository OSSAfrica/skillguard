"""Exercise the actual release handoff shell without network or GitHub writes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


class UpdateHandoff(unittest.TestCase):
    def run_handoff(self, existing, verified=True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        log = base/'commands.jsonl'
        for name, code in {
            'git': '''
if args[0]=='diff': sys.exit(1)
if args[0]=='rev-parse': print('a'*40)
elif args[0]=='ls-remote' and os.environ['EXISTING']=='1': print('b'*40+'\\trefs/heads/automation/plugin-runtime-v9.0.0')
elif args[0] not in ('ls-remote','push'): sys.exit(90)
''',
            'gh': '''
if args[:2]==['api','graphql']: print(json.dumps({'data':{'createCommitOnBranch':{'commit':{'oid':'c'*40,'signature':{'isValid':True}}}}}))
elif args[0]=='api': print(os.environ['VERIFIED'])
elif args[:2]!=['workflow','run']: sys.exit(91)
''',
            'jq': '''
if args[0]=='-e': print('true')
else: print('c'*40)
''',
        }.items():
            script = '#!'+sys.executable+'\nimport json,os,sys\nargs=sys.argv[1:]\nwith open(os.environ["COMMAND_LOG"],"a") as f: f.write(json.dumps([os.path.basename(sys.argv[0])]+args)+"\\n")\n'+code
            path = base/name
            path.write_text(script)
            path.chmod(0o700)
        (base/'python3').symlink_to(sys.executable)
        workflow = (ROOT/'.github/workflows/release.yml').read_text()
        step = workflow.split('      - name: Prepare maintainer handoff and request branch CI\n',1)[1].split('\n  notify:',1)[0]
        shell = textwrap.dedent(step.split('        run: |\n',1)[1])
        env = dict(os.environ, PATH=str(base)+os.pathsep+os.environ['PATH'],
                   COMMAND_LOG=str(log), EXISTING=str(int(existing)), VERIFIED=str(verified).lower(),
                   RELEASE_TAG='v9.0.0', GITHUB_REPOSITORY='OSSAfrica/skillguard',
                   RUNNER_TEMP=str(base), GITHUB_STEP_SUMMARY=str(base/'summary.md'))
        result = subprocess.run(['bash','-euo','pipefail','-c',shell],cwd=ROOT,env=env,capture_output=True,text=True,timeout=20)
        commands = [json.loads(line) for line in log.read_text().splitlines()]
        summary = (base/'summary.md').read_text() if (base/'summary.md').exists() else ''
        return result,commands,summary

    def test_existing_signed_branch_without_pr_is_reused(self):
        result,commands,summary = self.run_handoff(existing=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn(['git','push','origin','HEAD:refs/heads/automation/plugin-runtime-v9.0.0'],commands)
        self.assertFalse(any(c[:3]==['gh','api','graphql'] for c in commands))
        self.assertFalse(any(c[:2]==['gh','pr'] for c in commands))
        self.assertIn('b'*40,summary)
        self.assertIn('compare/main...automation/plugin-runtime-v9.0.0?expand=1',summary)
        self.assertIn(['gh','workflow','run','ci.yml','--ref','automation/plugin-runtime-v9.0.0'],commands)

    def test_fresh_branch_produces_handoff_without_pr_permission(self):
        result,commands,summary = self.run_handoff(existing=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(any(c[:3]==['gh','api','graphql'] for c in commands))
        self.assertFalse(any(c[:2]==['gh','pr'] for c in commands))
        self.assertIn('c'*40,summary)
        self.assertIn('No PR is created or approved by Actions',summary)

    def test_unsigned_existing_branch_stops_before_handoff(self):
        result,commands,summary = self.run_handoff(existing=True,verified=False)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(summary,'')
        self.assertFalse(any(c[:3]==['gh','workflow','run'] for c in commands))
