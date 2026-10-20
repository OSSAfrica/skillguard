# Claude Code, Codex and OpenCode integrations

For scanning in ordinary coding sessions, use the
[native plugin installation](native-plugins.md). The profiles below provide a
separate, more restrictive execution boundary.

SkillGuard provides shared MCP tools and opt-in local launchers for Claude Code,
Codex and OpenCode. The launcher profiles remove general command executors and
connect a protected SkillGuard server. Normal client commands and global settings
are left alone.

These are deliberately restricted coding profiles: agents can inspect and edit
files, scan documentation and assess proposed actions. They cannot run ordinary
shell commands, tests or installers through their native command tools. Running
arbitrary interpreters while claiming to gate every package installation would
leave a bypass. Use the optional controlled install tool only with a separately
isolated, operator-configured runtime.

## Install and launch

Requirements: Python 3.10+, a reviewed SkillGuard binary, and the exact client
versions validated for this profile:

| Client | Validated version | Integration |
| --- | --- | --- |
| Claude Code | 2.1.304 | Restricted mode, explicit file tools, strict MCP configuration, quarantine hook |
| Codex | 0.163.0 | Shell/unified execution and Code Mode disabled, explicit MCP configuration |
| OpenCode | 2.1.0 | Private standalone server/config directory, native permissions, direct MCP tools, plugin |

From a reviewed checkout:

```sh
go build -o /tmp/skillguard-clients .
python3 -I integrations/clients/install.py \
  --scanner /tmp/skillguard-clients \
  --prefix "$HOME/.local/share/skillguard/client-integrations"
```

Choose a new empty prefix outside the workspace. The installer refuses to replace
an existing installation. Add the installation's `bin` directory to your PATH or
invoke a launcher by its absolute path:

```sh
~/.local/share/skillguard/client-integrations/bin/skillguard-claude --check
~/.local/share/skillguard/client-integrations/bin/skillguard-codex --check
~/.local/share/skillguard/client-integrations/bin/skillguard-opencode --check

~/.local/share/skillguard/client-integrations/bin/skillguard-opencode \
  --root /path/to/project --model provider/model
```

The default root is the current directory. Omit `--check` to launch. `--print
--prompt 'Inspect llms.txt using SkillGuard and explain the findings'` selects
Claude print, Codex exec or OpenCode run mode. Provider authentication remains the
client's responsibility. OpenCode's private config omits custom global providers;
use a built-in provider/authentication or customize a reviewed deployment profile.

A version mismatch or failed MCP preflight prevents launch. Retest and update the
version pin before accepting an upgrade. Installation does not edit global agent
configuration, shell startup files, PATH or branch protection. Remove the
installation prefix and any launcher symlinks to uninstall.

## MCP contract

`skillguard mcp` serves newline-delimited JSON-RPC over stdio using MCP
2025-06-18. It writes protocol responses to stdout. Tool responses include both
JSON text and `structuredContent` for clients that support it.

| Tool | Model supplies | Result and authority |
| --- | --- | --- |
| `skillguard_scan_document` | `content`, optional `source` label | Static offline report, extracted candidates, coverage; `execution_authorized:false` |
| `skillguard_assess_action` | `action` with exact argv or Bash text | Existing versioned `allow`/`review`/`deny` assessment; never executes |
| `skillguard_install_action` | Exact `argv` only | Optional protected gate; `executed` or `withheld`, or a tool error |

Assessment requires fixed operator configuration:

```sh
skillguard mcp --policy /protected/policy.json --context /protected/context.json
```

The context file contains `schema_version:1`, absolute `target_root` and `cwd`,
`environment`, `context_profile`, and `inputs`, following the
[action assessment contract](action-assessment.md). Context and policy must live
outside the target. The model cannot override them in a tool call. The default
launcher creates an empty isolation profile and no reviewed actions, so host
installation receives review/partial coverage rather than a fabricated allow.

Scanning has no registry network access or dependency-file reads. A source label
is evidence, not a fetch target. A clean scan does not prove a package is safe,
and package existence does not prove legitimacy. Assessment uses its protected
registry policy and explicit operator review; it never registers missing names.
Tool failures return `isError:true` with `SG_MCP_TOOL_FAILED` and fixed guidance.
Do not interpret transport success, an empty report or an error as permission.

## Optional controlled installation

Only an operator may enable installation:

```sh
skillguard-opencode --root /isolated/project \
  --policy /protected/policy.json --context /protected/context.json \
  --guard-config /protected/guard.json \
  --guard-python /protected/python3 --guard-script /protected/guard.py
```

See [the harness deployment contract](harness-integration.md) for guard config,
review procedures, isolation and executable hashes. All guard paths must be
absolute and outside the target. The tool passes only an action JSON object to
the fixed Python guard on stdin, with an empty process environment and no shell.
The guard derives context, assesses, checks its response and rechecks hashes
immediately before dispatch. Review, deny, malformed responses and changed inputs
withhold execution.

The MCP call has a 30-second deadline. On Unix, cancellation terminates the gate's
process group. An interrupted call may have partially executed; inspect the
runtime before retrying. Execution is unavailable through MCP on Windows;
read-only tools remain available. No installer output or environment secrets are
returned to the model.

## Enforcement and limitations

MCP registration alone is advisory. Adding these tools to an unrestricted chat or
coding client does not intercept its other tools. Prompt instructions or a skill
can encourage use but cannot enforce use. The supplied launchers restrict the
native execution paths as well as providing the MCP tools.

Claude restricted mode and explicit tools remove native executors; its synchronous
quarantine hook also denies commands with `onFailure:block`. Codex profiles disable
native executors instead of relying on hooks: Codex documents circumstances where
hook failures proceed. OpenCode sets `codemode:false` for SkillGuard and denies
`execute`, shell and subagents through native permissions. Its plugin adds shell
creation/execution denial; native restrictions remain when the plugin is absent.

Profiles and runtime code must be installed from a reviewed source outside the
writable target. This is a client tool boundary, not an OS sandbox. It cannot
protect against a compromised client, trusted administrator configuration, another
process changing protected files, unsafe provider/plugin code, or a human using
ordinary client commands. External isolation is still required for real installs,
network restrictions, secret separation and concurrent-write protection. Editing
project code can also affect what humans or CI run later; review remains necessary.

The repeatable installed-client smoke suite validates noninteractive sessions.
Interactive launchers use the same restriction settings, but interactive UI and
all possible client features are not certified. See
[the validation record](client-integration-validation.md).

## References

- [Claude Code hook control and failures](https://code.claude.com/docs/en/hooks)
- [Codex hooks and failure behavior](https://learn.chatgpt.com/docs/hooks)
- [OpenCode MCP servers and direct exposure](https://dev.opencode.ai/v2/docs/mcp-servers/)
- [OpenCode permissions](https://dev.opencode.ai/v2/docs/permissions/)
- [OpenCode 2.1.0 MCP registration source](https://github.com/anomalyco/opencode/blob/v2.1.0/packages/core/src/tool/mcp.ts)
- [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
