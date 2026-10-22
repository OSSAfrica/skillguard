"""Real MCP -> Python gate -> real assessment -> fake executor contract test."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def digest(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(os.name == "posix" and os.environ.get("SKILLGUARD_TEST_SCANNER"), "set reviewed scanner path on Unix")
class MCPGate(unittest.TestCase):
    def test_only_exact_review_reaches_fake_executor_and_tampering_withholds(self):
        scanner = str(Path(os.environ["SKILLGUARD_TEST_SCANNER"]).resolve(strict=True))
        guard = Path(__file__).resolve().parents[2] / "examples/harness/guard.py"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            target = base / "target"
            target.mkdir()
            marker = target / "fake-installer-ran"
            executor = base / "fake-pip"
            # This is an explicit synthetic executor; never invoke npm/pip here.
            executor.write_text("#!" + str(Path(sys.executable).resolve()) + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('one synthetic dispatch')\n")
            executor.chmod(0o700)
            policy_path, config_path = base / "policy.json", base / "guard.json"
            policy = {"schema_version": 1, "id": "synthetic-only", "version": "1", "max_age_seconds": 60, "isolated_profiles": ["synthetic-no-packages"], "reviewed_actions": [], "require_metadata": False, "verification": {"schema_version": 1, "registries": [{"id": "fixture", "ecosystem": "pypi", "metadata_url": "https://registry.invalid/pypi", "install_url": "https://registry.invalid/simple", "packages": ["synthetic"]}]}}
            policy_path.write_text(json.dumps(policy))
            config_path.write_text(json.dumps({"schema_version": 1, "target_root": str(target), "cwd": str(target), "policy": str(policy_path), "scanner": scanner, "scanner_sha256": digest(scanner), "profile": "synthetic-no-packages", "environment": {}, "inputs": [], "executables": {"pip": {"path": str(executor), "sha256": digest(executor)}}}))
            argv = ["pip", "install", "--only-binary=:all:", "--no-deps", "--index-url", "https://registry.invalid/simple", "synthetic==1.0.0"]
            action = {"mode": "argv", "argv": argv}
            command = [scanner, "mcp", "--guard-config", str(config_path), "--guard-python", str(Path(sys.executable).resolve()), "--guard-script", str(guard)]

            def call(arguments):
                messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "skillguard_install_action", "arguments": arguments}}]
                process = subprocess.run(command, input="".join(json.dumps(m) + "\n" for m in messages), capture_output=True, text=True, timeout=15, check=False)
                self.assertEqual(process.returncode, 0)
                return json.loads(process.stdout.splitlines()[-1])["result"]

            self.assertEqual(call({"argv": argv})["structuredContent"]["status"], "withheld")
            self.assertFalse(marker.exists())
            assessed = subprocess.run([str(Path(sys.executable).resolve()), "-I", str(guard), "--config", str(config_path), "--assess-only"], input=json.dumps(action), capture_output=True, text=True, timeout=15, check=True)
            assessment = json.loads(assessed.stdout)["assessment"]
            self.assertEqual(assessment["decision"], "review")
            policy["reviewed_actions"] = [{"subject_fingerprint": assessment["subject_fingerprint"], "context_fingerprint": assessment["context_fingerprint"], "review_id": "synthetic-executor-review", "expires_at": "2099-01-01T00:00:00Z", "accept_mutable_artifacts": True}]
            policy_path.write_text(json.dumps(policy))
            allowed = call({"argv": argv})
            self.assertFalse(allowed["isError"])
            self.assertEqual(allowed["structuredContent"]["status"], "executed")
            self.assertEqual(marker.read_text(), "one synthetic dispatch")
            marker.unlink()
            self.assertEqual(call({"argv": argv[:-1] + ["synthetic==2.0.0"]})["structuredContent"]["status"], "withheld")
            self.assertFalse(marker.exists())
            self.assertTrue(call({"argv": argv, "policy": "agent-selected"})["isError"])
            self.assertFalse(marker.exists())
            executor.write_text("changed executor")
            self.assertEqual(call({"argv": argv})["structuredContent"]["status"], "withheld")
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
