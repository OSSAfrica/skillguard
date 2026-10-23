#!/usr/bin/env python3
"""Deny Bash dispatch where the real execution context cannot be attested.

Install with the all-Bash matcher and onFailure=block. This deliberately does not
mint isolation claims from hook metadata, whitelist commands with regexes, or
return an allow based on a previously supplied scan result.
"""
import json
import sys


def main():
    # Read a bounded payload; no untrusted content is reflected in the reply.
    sys.stdin.buffer.read(1024 * 1024 + 1)
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "SkillGuard: Bash is quarantined. Use the operator-controlled isolated install tool; do not retry through another execution tool."}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
