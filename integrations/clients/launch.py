#!/usr/bin/env python3
"""Launch one installed client with SkillGuard's protected local profile.

This is an opt-in profile, not a global settings editor or OS sandbox. The
controlled install tool requires a separately configured isolated runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

TESTED = {"claude": "2.1.304", "codex": "0.163.0", "opencode": "2.1.0"}


def validated_version(client, output):
    expected = {"claude": TESTED["claude"] + " (Claude Code)",
                "codex": "codex-cli " + TESTED["codex"],
                "opencode": "opencode v" + TESTED["opencode"]}
    return output.strip() == expected[client]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def outside(path, root):
    return path != root and root not in path.parents


def prepare(args):
    root = Path(args.root).resolve(strict=True)
    state = Path(args.state_dir).resolve()
    scanner = Path(args.scanner).resolve(strict=True)
    if not root.is_dir() or not outside(state, root):
        raise ValueError("Profile state must be outside the target directory")
    if state.exists() and any(state.iterdir()) and not (state / "manifest.json").is_file():
        raise ValueError("Select an empty directory or a previously generated SkillGuard profile")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.chmod(0o700)
    for relative in ("skillguard", "quarantine.py", "opencode-plugin", "context.json", "policy.json", "claude-mcp.json", "claude-settings.json", "opencode.json", "manifest.json"):
        if (state / relative).is_symlink():
            raise ValueError("Profile artifacts cannot be symlinks")
    # Never run adapter code/binaries out of the writable target.
    binary = state / "skillguard"
    if scanner != binary and (not binary.exists() or hashlib.sha256(scanner.read_bytes()).digest() != hashlib.sha256(binary.read_bytes()).digest()):
        # A profile can already have an active server. Replace the inode instead
        # of overwriting a running executable (or failing with ETXTBSY on Linux).
        with tempfile.NamedTemporaryFile(dir=state, delete=False) as staged:
            staged_name = staged.name
        try:
            shutil.copy2(scanner, staged_name)
            os.chmod(staged_name, 0o700)
            os.replace(staged_name, binary)
        finally:
            Path(staged_name).unlink(missing_ok=True)
    binary.chmod(0o700)
    source = Path(__file__).resolve().parent
    hook = state / "quarantine.py"
    shutil.copy2(source.parents[1] / "examples/harness/claude_quarantine.py", hook)
    hook.chmod(0o600)
    plugin = state / "opencode-plugin"
    shutil.copytree(source / "opencode-plugin", plugin, dirs_exist_ok=True)
    for file in plugin.iterdir():
        file.chmod(0o600)
    python = str(Path(sys.executable).resolve())
    context_path = Path(args.context).resolve(strict=True) if args.context else state / "context.json"
    policy_path = Path(args.policy).resolve(strict=True) if args.policy else state / "policy.json"
    if bool(args.context) != bool(args.policy):
        raise ValueError("Select both protected context and policy")
    if not args.context:
        # No fabricated isolated profile: host assessments must withhold allow.
        write_json(context_path, {"schema_version": 1, "target_root": str(root), "cwd": str(root),
                                 "environment": {}, "context_profile": "", "inputs": []})
        write_json(policy_path, {"schema_version": 1, "id": "local-review-required", "version": "1",
                                "max_age_seconds": 60, "isolated_profiles": [], "reviewed_actions": [],
                                "require_metadata": False})
    selected = json.loads(context_path.read_text())
    if Path(selected["target_root"]).resolve(strict=True) != root:
        raise ValueError("Assessment context must describe the client target")
    for path in (context_path, policy_path):
        if not outside(path, root):
            raise ValueError("Policy and context must be outside the target")
    mcp = [str(binary), "mcp", "--policy", str(policy_path), "--context", str(context_path)]
    if args.guard_config:
        if not args.guard_python or not args.guard_script:
            raise ValueError("Controlled installation requires all three guard options")
        guard_selected = json.loads(Path(args.guard_config).read_text())
        if Path(guard_selected["target_root"]).resolve(strict=True) != root:
            raise ValueError("Controlled install context must match the client target")
        mcp += ["--guard-config", str(Path(args.guard_config).resolve(strict=True)),
                "--guard-python", str(Path(args.guard_python).resolve(strict=True)),
                "--guard-script", str(Path(args.guard_script).resolve(strict=True))]
    elif args.guard_python or args.guard_script:
        raise ValueError("Guard runtime options require a guard configuration")
    claude_mcp = state / "claude-mcp.json"
    claude_settings = state / "claude-settings.json"
    write_json(claude_mcp, {"mcpServers": {"skillguard": {"command": mcp[0], "args": mcp[1:]}}})
    write_json(claude_settings, {"permissions": {"deny": ["Bash", "PowerShell", "Agent", "Task"]},
        "hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell|Agent|Task", "hooks": [{
            "type": "command", "command": python, "args": ["-I", str(hook)],
            "timeout": 25, "onFailure": "block"}]}]}})
    rules = [{"action": "*", "resource": "*", "effect": "deny"}] + [
        {"action": action, "resource": "*", "effect": "allow"}
        for action in ("read", "edit", "glob", "grep", "skillguard_skillguard_scan_document",
                       "skillguard_skillguard_assess_action", "skillguard_skillguard_install_action")]
    opencode = {"mcp": {"servers": {"skillguard": {"type": "local", "command": mcp,
                "disabled": False, "codemode": False}}}, "plugins": [plugin.as_uri()],
                "permissions": rules, "default_agent": "skillguard",
                "agents": {"skillguard": {"description": "Coding with protected SkillGuard tools",
                            "mode": "primary", "permissions": rules}}}
    write_json(state / "opencode.json", opencode)
    manifest = {"schema_version": 1, "tested_versions": TESTED,
                "files": {str(path.relative_to(state)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (binary, hook, plugin / "index.mjs", plugin / "package.json")}}
    write_json(state / "manifest.json", manifest)
    return {"root": root, "state": state, "mcp": mcp, "claude_mcp": claude_mcp,
            "claude_settings": claude_settings, "opencode": opencode}


def mcp_health(command):
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "skillguard-profile-check", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
    result = subprocess.run(command, input="".join(json.dumps(item) + "\n" for item in requests),
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise ValueError("SkillGuard MCP health check failed; client was not started")
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    listed = next((r for r in replies if r.get("id") == 2), {})
    names = {tool["name"] for tool in listed.get("result", {}).get("tools", [])}
    if not {"skillguard_scan_document", "skillguard_assess_action"}.issubset(names):
        raise ValueError("Required SkillGuard MCP tools are unavailable")


def client_command(client, config, model=None, prompt=None, noninteractive=False):
    executable = shutil.which(client)
    if not executable:
        raise ValueError("Requested client is not installed")
    root = str(config["root"])
    env = dict(os.environ)
    env["PWD"] = root
    if client == "claude":
        command = [executable, "--restricted", "--setting-sources", "", "--settings", str(config["claude_settings"]),
                   "--strict-mcp-config", "--mcp-config", str(config["claude_mcp"]),
                   "--tools", "Read,Edit,Write,Glob,Grep", "--allowedTools", "mcp__skillguard__*"]
        if noninteractive:
            command += ["--print", "--output-format", "json"]
    elif client == "codex":
        command = [executable] + (["exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check"] if noninteractive else ["--no-daemon"])
        command += ["-C", root, "--sandbox", "workspace-write"]
        features = {"shell_tool": False, "unified_exec": False, "code_mode": False, "hooks": False,
                    "plugins": False, "apps": False, "multi_agent": False, "browser_use": False,
                    "computer_use": False, "shell_snapshot": False}
        for name, value in features.items():
            command += ["-c", f"features.{name}={str(value).lower()}"]
        command += ["-c", "sandbox_workspace_write.network_access=false", "-c", "sandbox_workspace_write.writable_roots=[]"]
        mcp = config["mcp"]
        # JSON strings/arrays are valid TOML values here; structured CLI arguments
        # avoid shell escaping or interpolating model text into commands.
        literal = "{skillguard={command=" + json.dumps(mcp[0]) + ",args=" + json.dumps(mcp[1:]) + "}}"
        command += ["-c", "mcp_servers=" + literal]
        if noninteractive:
            command += ["--json"]
    else:
        command = [executable] + (["run", "--standalone", "--format", "json"] if noninteractive else ["--standalone"])
        command += ["--agent", "skillguard"]
        # Isolate executable user/project configuration, retain data/auth storage.
        env["XDG_CONFIG_HOME"] = str(config["state"] / "xdg-config")
        for key in ("OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "OPENCODE_CLI_CONFIG_CONTENT"):
            env.pop(key, None)
        env["OPENCODE_CONFIG_CONTENT"] = json.dumps(config["opencode"])
        env["OPENCODE_CONFIG_PROJECT_DISABLE"] = "true"
        env["OPENCODE_DISABLE_PROJECT_CONFIG"] = "true"
    if model:
        command += ["--model", model]
    if prompt:
        command.append(prompt)
    return command, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", choices=TESTED)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--root", default=os.getcwd())
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--policy")
    parser.add_argument("--context")
    parser.add_argument("--guard-config")
    parser.add_argument("--guard-python")
    parser.add_argument("--guard-script")
    parser.add_argument("--model")
    parser.add_argument("--prompt")
    parser.add_argument("--print", action="store_true", dest="noninteractive")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        config = prepare(args)
        mcp_health(config["mcp"])
        command, env = client_command(args.client, config, args.model, args.prompt, args.noninteractive)
        version = subprocess.run([command[0], "--version"], capture_output=True, text=True, timeout=10, check=False)
        if version.returncode != 0 or not validated_version(args.client, version.stdout):
            raise ValueError("Client version differs from the validated version; retest before enabling this profile")
        if args.check:
            print(json.dumps({"status": "ready", "client": args.client, "tested_version": TESTED[args.client],
                              "state_directory": str(config["state"]), "command": command,
                              "note": "Direct execution is restricted; installs require a configured isolated gate."}))
            return 0
        os.chdir(config["root"])
        os.execvpe(command[0], command, env)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, json.JSONDecodeError):
        print("SkillGuard profile could not be validated; client was not started.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
