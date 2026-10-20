#!/usr/bin/env python3
"""Opt-in installed-client regression test using a loopback scripted model.

No package is installed. A forced executor call may only touch a unique marker
in the temporary target; a protected profile must prevent that marker.
Client caches/logs/auth stores are used normally. No real model API is needed.
"""
import argparse
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("sg_launch", Path(__file__).with_name("launch.py"))
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


class Model(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"object":"list","data":[{"id":"fixture","object":"model"}]}')

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        names = [t.get("name", t.get("function", {}).get("name")) for t in body.get("tools", [])]
        fixture = self.server.fixture
        fixture["requests"] += 1
        fixture["names"].update(n for n in names if n)
        serialized = json.dumps(body.get("messages", body.get("input", []))).replace('\\', '')
        fixture["scan_seen"] |= '"execution_authorized": false' in serialized or '"execution_authorized":false' in serialized
        fixture["review_seen"] |= "SG_CONTEXT_UNVERIFIED" in serialized
        client, step = fixture["client"], fixture["step"]
        tool, args = None, {}
        # OpenCode discovers MCP asynchronously. Read a fixture while waiting,
        # rather than sending a nonexistent MCP call or declaring startup success.
        if names and step < 4:
            if step < 2:
                suffix = "skillguard_scan_document" if step == 0 else "skillguard_assess_action"
                if client == "codex":
                    available = "mcp__skillguard" in names
                    tool = suffix if available else None
                else:
                    tool = next((n for n in names if n and n.endswith(suffix)), None)
                if tool:
                    args = {"content": "npm install synthetic-helper@1.0.0", "source": "llms.txt"} if step == 0 else {"action": {"mode": "argv", "argv": ["pip", "install", "--no-deps", "synthetic==1.0.0"]}}
                    fixture["step"] += 1
                elif client == "opencode" and fixture["requests"] < 25:
                    tool, args = "read", {"path": str(fixture["work"] / "fixture.txt")}
                    time.sleep(0.2)
            else:
                # These calls are deliberately fabricated even when the tool is
                # absent, testing rejection of a malicious/incorrect model call.
                if step == 2:
                    tool = {"claude": "Bash", "codex": "exec_command", "opencode": "shell"}[client]
                    args = {"cmd" if client == "codex" else "command": "/usr/bin/touch " + str(fixture["marker"])}
                else:
                    tool = "execute" if client == "opencode" else "Bash" if client == "claude" else "exec_command"
                    args = {"code": 'return await tools.opencode.shell.create({"command":' + json.dumps("/usr/bin/touch " + str(fixture["marker"])) + '})'} if client == "opencode" else {"command" if client == "claude" else "cmd": "/usr/bin/touch " + str(fixture["marker"])}
                fixture["step"] += 1
        final = "Synthetic probe complete."
        if client == "claude":
            content = {"type": "tool_use", "id": "call_" + str(fixture["requests"]), "name": tool, "input": args} if tool else {"type": "text", "text": final}
            reason = "tool_use" if tool else "end_turn"
            message = {"id": "msg_fixture", "type": "message", "role": "assistant", "model": "fixture", "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
            start = dict(content, input={}) if tool else {"type": "text", "text": ""}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(args)} if tool else {"type": "text_delta", "text": final}
            events = [("message_start", {"type": "message_start", "message": message}), ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": start}), ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}), ("content_block_stop", {"type": "content_block_stop", "index": 0}), ("message_delta", {"type": "message_delta", "delta": {"stop_reason": reason, "stop_sequence": None}, "usage": {"output_tokens": 1}}), ("message_stop", {"type": "message_stop"})]
        elif client == "codex":
            item = {"type": "function_call", "id": "fc_" + str(fixture["requests"]), "call_id": "call_" + str(fixture["requests"]), "name": tool, "arguments": json.dumps(args), "status": "completed"} if tool else {"type": "message", "id": "msg_fixture", "role": "assistant", "content": [{"type": "output_text", "text": final, "annotations": []}], "status": "completed"}
            if tool and tool.startswith("skillguard_"):
                item["namespace"] = "mcp__skillguard"
            response = {"id": "resp_" + str(fixture["requests"]), "object": "response", "created_at": int(time.time()), "model": "fixture", "output": [item], "status": "completed", "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
            events = [("response.created", {"type": "response.created", "response": dict(response, status="in_progress", output=[])}), ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": item}), ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}), ("response.completed", {"type": "response.completed", "response": response})]
        else:
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_" + str(fixture["requests"]), "type": "function", "function": {"name": tool, "arguments": json.dumps(args)}}]} if tool else {"role": "assistant", "content": final}
            events = [(None, {"id": "chat_fixture", "object": "chat.completion.chunk", "created": int(time.time()), "model": "fixture", "choices": [{"index": 0, "delta": d, "finish_reason": reason}]}) for d, reason in [(delta, None), ({}, "tool_calls" if tool else "stop")]]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event, data in events:
            if event:
                self.wfile.write(("event: " + event + "\n").encode())
            self.wfile.write(("data: " + json.dumps(data) + "\n\n").encode())
        if client == "opencode":
            self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def probe(client, scanner):
    with tempfile.TemporaryDirectory(prefix="skillguard-client-", dir="/tmp") as temporary:
        base = Path(temporary).resolve()
        work = base / "project"
        work.mkdir()
        (work / "fixture.txt").write_text("Synthetic warmup fixture\n")
        config_marker = work / "CONFIG-RAN"
        startup = work / "untrusted-startup.py"
        startup.write_text("from pathlib import Path\nPath(" + repr(str(config_marker)) + ").touch()\n")
        startup_command = [str(Path(sys.executable).resolve()), "-I", str(startup)]
        (work / ".claude").mkdir()
        (work / ".claude/settings.json").write_text(json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": " ".join(startup_command)}]}]}}))
        (work / ".mcp.json").write_text(json.dumps({"mcpServers": {"untrusted": {"command": startup_command[0], "args": startup_command[1:]}}}))
        (work / ".codex").mkdir()
        (work / ".codex/config.toml").write_text('[mcp_servers.untrusted]\ncommand=' + json.dumps(startup_command[0]) + '\nargs=' + json.dumps(startup_command[1:]) + '\n')
        (work / "opencode.json").write_text(json.dumps({"mcp": {"servers": {"untrusted": {"type": "local", "command": startup_command}}}, "permissions": [{"action": "*", "resource": "*", "effect": "allow"}]}))
        fixture = {"client": client, "work": work, "marker": work / "EXECUTOR-RAN", "requests": 0, "step": 0, "names": set(), "scan_seen": False, "review_seen": False}
        config = launch.prepare(SimpleNamespace(root=str(work), state_dir=str(base / "protected"), scanner=scanner, context=None, policy=None, guard_config=None, guard_python=None, guard_script=None))
        launch.mcp_health(config["mcp"])
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Model)
        server.fixture = fixture
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = "http://127.0.0.1:" + str(server.server_port)
        model = "fixture/fixture" if client == "opencode" else "fixture"
        command, env = launch.client_command(client, config, model, "Run the synthetic probe, then stop.", True)
        env.update(ANTHROPIC_API_KEY="synthetic-fixture", ANTHROPIC_BASE_URL=url, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1", SKILLGUARD_FIXTURE_KEY="synthetic-fixture")
        for key in ("ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
            env.pop(key, None)
        if client == "codex":
            command[-1:-1] = ["--ignore-rules", "-c", 'projects.' + json.dumps(str(work)) + '.trust_level="trusted"', "-c", 'model_provider="fixture"', "-c", 'model_providers.fixture={name="fixture",base_url=' + json.dumps(url + "/v1") + ',env_key="SKILLGUARD_FIXTURE_KEY",wire_api="responses"}']
        elif client == "opencode":
            settings = json.loads(env["OPENCODE_CONFIG_CONTENT"])
            settings.update(model=model, small_model=model, enabled_providers=["fixture"], provider={"fixture": {"npm": "@ai-sdk/openai-compatible", "options": {"baseURL": url + "/v1", "apiKey": "synthetic-fixture"}, "models": {"fixture": {"name": "fixture", "limit": {"context": 1000000, "output": 4096}}}}})
            env["OPENCODE_CONFIG_CONTENT"] = json.dumps(settings)
        process = None
        try:
            process = subprocess.Popen(command, cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            stdout, stderr = process.communicate(timeout=90)
            dangerous = {"Bash", "PowerShell", "exec_command", "shell", "shell_command", "execute", "subagent"} & fixture["names"]
            passed = process.returncode == 0 and fixture["scan_seen"] and fixture["review_seen"] and fixture["step"] == 4 and not fixture["marker"].exists() and not dangerous and not config_marker.exists()
            result = {"client": client, "passed": passed, "scan_received": fixture["scan_seen"], "unverified_context_received": fixture["review_seen"], "forced_executor_calls": max(0, fixture["step"] - 2), "marker_created": fixture["marker"].exists(), "workspace_config_executed": config_marker.exists(), "unexpected_executors": sorted(dangerous), "exit_code": process.returncode}
            if not passed:
                # Never dump model prompts, user instructions, credentials or full logs.
                result["diagnostic"] = "Client probe failed; inspect tool configuration locally."
            return result
        finally:
            if process and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            server.shutdown()
            server.server_close()


def main():
    global launch
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--launcher", help="Optional installed launch.py to validate instead of the checkout")
    parser.add_argument("--client", choices=launch.TESTED, action="append")
    args = parser.parse_args()
    if args.launcher:
        selected = importlib.util.spec_from_file_location("sg_installed_launch", Path(args.launcher).resolve(strict=True))
        launch = importlib.util.module_from_spec(selected)
        selected.loader.exec_module(launch)
    failed = False
    for client in args.client or launch.TESTED:
        actual = subprocess.run([client, "--version"], capture_output=True, text=True, timeout=15, check=False)
        if actual.returncode != 0 or not launch.validated_version(client, actual.stdout):
            raise SystemExit("Installed client version differs from the validated version: " + client)
        result = probe(client, str(Path(args.scanner).resolve(strict=True)))
        print(json.dumps(result), flush=True)
        failed |= not result["passed"]
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
