"""Security contracts for local profiles; no installed clients required."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("launch", Path(__file__).with_name("launch.py"))
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


class Profiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "project"
        self.root.mkdir()
        self.scanner = self.base / "scanner"
        self.scanner.write_bytes(b"synthetic scanner")
        self.args = SimpleNamespace(root=str(self.root), state_dir=str(self.base / "protected"), scanner=str(self.scanner), context=None, policy=None, guard_config=None, guard_python=None, guard_script=None)

    def test_agent_cannot_own_policy_or_runtime(self):
        self.args.state_dir = str(self.root / "profile")
        with self.assertRaises(ValueError):
            launch.prepare(self.args)
        self.args.state_dir = str(self.base / "link")
        (self.base / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            launch.prepare(self.args)

    def test_existing_unrelated_directory_is_preserved(self):
        directory = Path(self.args.state_dir)
        directory.mkdir()
        (directory / "unrelated").write_text("keep me")
        with self.assertRaises(ValueError):
            launch.prepare(self.args)
        self.assertEqual((directory / "unrelated").read_text(), "keep me")

    def test_no_host_execution_authority_is_fabricated(self):
        config = launch.prepare(self.args)
        context = json.loads((config["state"] / "context.json").read_text())
        policy = json.loads((config["state"] / "policy.json").read_text())
        self.assertEqual(context["context_profile"], "")
        self.assertEqual(policy["reviewed_actions"], [])
        self.assertEqual(policy["isolated_profiles"], [])
        self.assertNotIn("--guard-config", config["mcp"])

    def test_all_clients_remove_general_executors_and_select_protected_tools(self):
        config = launch.prepare(self.args)
        with patch.object(launch.shutil, "which", return_value="/trusted/client"), patch.dict(os.environ, {"OPENCODE_CONFIG": "/untrusted/config", "OPENCODE_CONFIG_DIR": "/untrusted/plugins", "OPENCODE_CLI_CONFIG_CONTENT": "untrusted"}):
            claude, _ = launch.client_command("claude", config)
            self.assertIn("--restricted", claude)
            self.assertIn("--strict-mcp-config", claude)
            self.assertNotIn("Bash", claude[claude.index("--tools") + 1])
            codex, _ = launch.client_command("codex", config, noninteractive=True)
            for option in ("features.shell_tool=false", "features.unified_exec=false", "features.code_mode=false", "features.hooks=false", "features.apps=false"):
                self.assertIn(option, codex)
            self.assertIn("--ignore-user-config", codex)
            opencode, env = launch.client_command("opencode", config)
            self.assertIn("--standalone", opencode)
            self.assertEqual(env["PWD"], str(self.root))
            self.assertEqual(env["XDG_CONFIG_HOME"], str(config["state"] / "xdg-config"))
            self.assertNotIn("OPENCODE_CONFIG", env)
            self.assertNotIn("OPENCODE_CONFIG_DIR", env)
            self.assertNotIn("OPENCODE_CLI_CONFIG_CONTENT", env)
            self.assertFalse(config["opencode"]["mcp"]["servers"]["skillguard"]["codemode"])
            allows = {r["action"] for r in config["opencode"]["permissions"] if r["effect"] == "allow"}
            self.assertTrue({"execute", "shell", "subagent", "external_directory"}.isdisjoint(allows))

    def test_missing_or_invalid_mcp_does_not_pass_preflight(self):
        with patch.object(launch.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout='{"id":2,"result":{"tools":[]}}\n')):
            with self.assertRaises(ValueError):
                launch.mcp_health(["/synthetic"])
        with self.assertRaises(OSError):
            launch.mcp_health([str(self.base / "missing")])


if __name__ == "__main__":
    unittest.main()
