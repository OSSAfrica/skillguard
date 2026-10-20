#!/usr/bin/env python3
"""Reference synchronous tool boundary for an operator-isolated coding harness.

No model-supplied policy/profile/environment/inputs are accepted. Deployment must
supply isolation described in docs/harness-integration.md; this is not a sandbox.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import stat
import time
from datetime import datetime

LIMIT = 4 * 1024 * 1024


class Withheld(Exception):
    """A fixed, non-sensitive failure reason suitable for a tool reply."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Withheld("duplicate_json_key")
        result[key] = value
    return result


def decode(data):
    if len(data) > LIMIT:
        raise Withheld("json_limit")
    try:
        return json.loads(data, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Withheld("invalid_json") from exc


def digest_file(path):
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise Withheld("non_regular_file")
            result = hashlib.sha256()
            while True:
                part = source.read(1024 * 1024)
                if not part:
                    break
                result.update(part)
            return "sha256:" + result.hexdigest()
    except OSError as exc:
        raise Withheld("file_unavailable") from exc


def inside(path, root):
    return path == root or root in path.parents


def load_config(filename):
    try:
        path = Path(filename).resolve(strict=True)
        if path.stat().st_size > 65536:
            raise Withheld("configuration_limit")
        config = decode(path.read_bytes())
        required = {"schema_version", "target_root", "cwd", "policy", "scanner",
                    "scanner_sha256", "profile", "environment", "inputs", "executables"}
        if not isinstance(config, dict) or set(config) != required or config["schema_version"] != 1:
            raise Withheld("invalid_configuration")
        root = Path(config["target_root"]).resolve(strict=True)
        cwd = Path(config["cwd"]).resolve(strict=True)
        policy = Path(config["policy"]).resolve(strict=True)
        scanner = Path(config["scanner"]).resolve(strict=True)
        if not inside(cwd, root) or any(inside(p, root) for p in (path, policy, scanner)):
            raise Withheld("unprotected_configuration")
        for field in ("target_root", "cwd", "policy", "scanner"):
            if not Path(config[field]).is_absolute():
                raise Withheld("absolute_paths_required")
        if not isinstance(config["environment"], dict) or not isinstance(config["inputs"], list):
            raise Withheld("invalid_configuration")
        if not isinstance(config["profile"], str) or not config["profile"]:
            raise Withheld("isolated_profile_required")
        if not isinstance(config["executables"], dict) or not config["executables"]:
            raise Withheld("invalid_configuration")
        for tool, value in config["executables"].items():
            if tool not in ("npm", "pip", "pip3") or set(value) != {"path", "sha256"}:
                raise Withheld("invalid_executable_mapping")
            executable = Path(value["path"]).resolve(strict=True)
            if not Path(value["path"]).is_absolute() or inside(executable, root):
                raise Withheld("unprotected_executable")
            if digest_file(executable) != value["sha256"]:
                raise Withheld("executable_changed")
        if digest_file(scanner) != config["scanner_sha256"]:
            raise Withheld("scanner_changed")
        config["_config_path"] = str(path)
        config["_config_sha256"] = digest_file(path)
        return config
    except (OSError, KeyError, TypeError, AttributeError, RuntimeError) as exc:
        raise Withheld("configuration_unavailable") from exc


def wire_hash(action):
    # Action is a Go struct: mode, argv, omitted command. Match encoding/json's
    # literal escaping, including HTML and U+2028/U+2029, without shell parsing.
    data = json.dumps(action, separators=(",", ":"), ensure_ascii=False)
    for raw, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                         ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        data = data.replace(raw, escaped)
    return "sha256:" + hashlib.sha256(data.encode()).hexdigest()


def snapshot(config):
    result = {"config": digest_file(config["_config_path"]),
              "policy": digest_file(config["policy"]),
              "scanner": digest_file(config["scanner"]),
              "real_cwd": str(Path(config["cwd"]).resolve(strict=True)),
              "real_root": str(Path(config["target_root"]).resolve(strict=True))}
    if result["config"] != config["_config_sha256"] or result["scanner"] != config["scanner_sha256"]:
        raise Withheld("protected_configuration_changed")
    root = Path(config["cwd"]).resolve(strict=True)
    for item in config["inputs"]:
        path = root / item["path"]
        resolved = path.resolve(strict=True)
        if not inside(resolved, root) or path.stat().st_size > 1024 * 1024:
            raise Withheld("input_boundary")
        result["input:" + item["path"]] = digest_file(path)
    for tool, value in config["executables"].items():
        result["executable:" + tool] = digest_file(value["path"])
        if result["executable:" + tool] != value["sha256"]:
            raise Withheld("executable_changed")
    return result


def scan(config, request):
    try:
        process = subprocess.run(
            [config["scanner"], "assess", "--policy", config["policy"]],
            input=json.dumps(request).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=config["cwd"], env={}, timeout=20,
            check=False)
        return process.returncode, process.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Withheld("scanner_unavailable_or_timeout") from exc


def validate_response(code, data, action, before):
    result = decode(data)
    if not isinstance(result, dict):
        raise Withheld("invalid_assessment")
    required_fields = {"schema_version", "engine_version", "ruleset_version", "assessed_at", "expires_at",
                       "status", "decision", "policy_id", "policy_version", "policy_fingerprint",
                       "subject_fingerprint", "context_fingerprint", "evidence_fingerprint",
                       "decision_fingerprint", "evidence_trust", "rules", "checks", "inputs", "dependencies"}
    if not required_fields.issubset(result) or set(result) - required_fields - {"review_id", "verification"}:
        raise Withheld("invalid_assessment_schema")
    if result["evidence_trust"] != "untrusted_data" or not isinstance(result["rules"], list) or not isinstance(result["dependencies"], list):
        raise Withheld("invalid_assessment_schema")
    if code != 0 or result.get("status") != "complete" or result.get("decision") != "allow":
        raise Withheld("assessment_withheld")
    if type(result.get("schema_version")) is not int or result.get("schema_version") != 1 or result.get("ruleset_version") != "action-v1":
        raise Withheld("unsupported_assessment")
    if result.get("subject_fingerprint") != wire_hash(action) or not result.get("review_id"):
        raise Withheld("assessment_subject_mismatch")
    for field in ("context_fingerprint", "policy_fingerprint", "decision_fingerprint", "evidence_fingerprint"):
        value = result.get(field, "")
        if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
            raise Withheld("assessment_binding_invalid")
        try:
            bytes.fromhex(value[7:])
        except ValueError as exc:
            raise Withheld("assessment_binding_invalid") from exc
    unsigned = dict(result)
    unsigned["decision_fingerprint"] = ""
    if wire_hash(unsigned) != result["decision_fingerprint"]:
        raise Withheld("assessment_digest_invalid")
    try:
        now = time.time()
        expiry = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
        observation = datetime.fromisoformat(result["assessed_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or observation.tzinfo is None:
            raise Withheld("assessment_time_invalid")
        expires, assessed = expiry.timestamp(), observation.timestamp()
        if not assessed <= now < expires or expires - assessed > 300:
            raise Withheld("assessment_expired")
    except (ValueError, KeyError, TypeError) as exc:
        raise Withheld("assessment_time_invalid") from exc
    checks = result.get("checks")
    if not isinstance(checks, list) or not checks:
        raise Withheld("assessment_checks_missing")
    required_checks = {"static_action_inputs", "operator_review"}
    by_id = {check.get("id"): check for check in checks if isinstance(check, dict)}
    if len(by_id) != len(checks) or not required_checks.issubset(by_id) or "registry_metadata" not in by_id:
        raise Withheld("assessment_checks_missing")
    if any(by_id[name].get("required") is not True for name in required_checks):
        raise Withheld("assessment_checks_incomplete")
    for check in checks:
        if not isinstance(check, dict) or check.get("required") is True and check.get("status") != "complete":
            raise Withheld("assessment_checks_incomplete")
    facts = result.get("inputs")
    if not isinstance(facts, list):
        raise Withheld("assessment_inputs_missing")
    observed = {}
    for fact in facts:
        if not isinstance(fact, dict) or fact.get("status") != "read" or fact.get("path") in observed:
            raise Withheld("assessment_inputs_invalid")
        observed[fact.get("path")] = fact.get("sha256")
    expected = {key[6:]: value for key, value in before.items() if key.startswith("input:")}
    if observed != expected:
        raise Withheld("assessment_inputs_mismatch")
    return result


def execute(config, action, environment):
    tool = config["executables"][action["argv"][0]]["path"]
    # Never inherit the harness environment and never invoke a shell. The trusted
    # runtime/profile must constrain interpreter and package-manager configuration.
    return subprocess.run([tool, *action["argv"][1:]], cwd=config["cwd"],
                          env=environment, stdout=sys.stderr, stderr=sys.stderr, check=False).returncode


def guarded_run(config, action, scanner=scan, executor=execute, assess_only=False):
    if not isinstance(action, dict) or set(action) != {"mode", "argv"} or action.get("mode") != "argv":
        raise Withheld("argv_action_required")
    argv = action.get("argv")
    if not isinstance(argv, list) or not argv or len(argv) > 512 or any(
            not isinstance(arg, str) or len(arg) > 8192 or "\0" in arg for arg in argv):
        raise Withheld("invalid_action")
    if argv[0] not in config["executables"]:
        raise Withheld("tool_not_mapped")
    action = {"mode": "argv", "argv": list(argv)}
    before = snapshot(config)
    environment = dict(config["environment"])
    # These exact values become both assessment context and execution environment.
    environment["SKILLGUARD_EXECUTOR_SHA256"] = before["executable:" + argv[0]]
    environment["SKILLGUARD_ADAPTER_CONFIG_SHA256"] = before["config"]
    request = {"schema_version": 1, "target_root": config["target_root"],
               "cwd": config["cwd"], "action": action, "environment": environment,
               "context_profile": config["profile"], "inputs": config["inputs"]}
    code, data = scanner(config, request)
    if assess_only:
        if snapshot(config) != before:
            raise Withheld("context_changed_reassess")
        return {"status": "assessed_only", "scanner_exit_code": code, "assessment": decode(data)}
    result = validate_response(code, data, action, before)
    if snapshot(config) != before:
        raise Withheld("context_changed_reassess")
    # Recheck the short-lived decision immediately before dispatch. This does not
    # replace runtime protection against concurrent writes or mutable resolution.
    validate_response(code, data, action, before)
    return {"status": "executed", "decision_fingerprint": result["decision_fingerprint"],
            "exit_code": executor(config, action, environment)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--assess-only", action="store_true")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.check:
            snapshot(config)
            reply = {"status": "configuration_validated", "isolation": "operator_supplied",
                     "note": "Run denial and failure probes before enabling a harness."}
        else:
            reply = guarded_run(config, decode(sys.stdin.buffer.read(LIMIT + 1)), assess_only=args.assess_only)
        print(json.dumps(reply))
        return 0
    except (Withheld, OSError, KeyError, TypeError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, Withheld) else "adapter_failure"
        print(json.dumps({"status": "withheld", "reason": reason,
                          "next_step": "Resolve coverage or obtain an exact scoped operator review; reassess."}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
