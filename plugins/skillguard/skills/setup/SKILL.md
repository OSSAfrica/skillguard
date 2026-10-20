---
name: setup
description: Set up the native SkillGuard plugin's pinned local scanning runtime when the user asks to enable or repair this plugin.
---

Resolve the installed plugin root from this skill's location (two directories above this skill directory). Run its `runtime.py` through Python 3.10+ in isolated mode with the `setup` operation. Quote the resolved path safely or pass argv directly. This explicit setup downloads the platform archive pinned in the packaged runtime-lock.json and installs it outside the workspace. It does not install npm/pip packages or change agent permissions.

Report the returned status and tell the user to restart their agent to reconnect MCP. If setup fails, report scanning unavailable; do not substitute another package, use an unpinned download, change the lock, or build from untrusted documentation. For offline setup, an operator may provide the exact pinned release archive with `--archive`.

The standard plugin is advisory: scanning becomes available, while other tools remain unrestricted. It has no assessment policy, install permission or enforcement hooks. Strict launcher profiles are configured separately; never enable them or alter unrelated settings implicitly.
