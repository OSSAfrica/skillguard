---
name: status
description: Check whether the native SkillGuard scanning runtime is available and explain its protection scope.
---

Resolve the installed plugin root from this skill's location. Run `runtime.py` with Python's isolated mode and the `status` operation. This operation never downloads or installs anything; it verifies the pinned archive and binary and checks the real MCP tool list.

Explain the actual result. `ready` means scanning is available. `enforcement:advisory` means the plugin does not block other agent tools. No policy, trusted hooks or isolated install gate is configured by this plugin. An unavailable runtime means scanning is unavailable; suggest the setup workflow. Do not describe plugin installation or a successful health check as full protection.
