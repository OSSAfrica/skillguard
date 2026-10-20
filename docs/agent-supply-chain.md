# Agent supply-chain protections

[Documentation](README.md) / Supply-chain protections

AI-readable documentation is untrusted input even on a familiar vendor domain. Install
instructions can name nonexistent packages that someone later registers, or existing
packages whose relationship to the project has never been verified. Pinning and registry
existence alone cannot establish that relationship.

## Protection layers

| Layer        | Delivered behavior                                                                         | Guide                                               |
| ------------ | ------------------------------------------------------------------------------------------ | --------------------------------------------------- |
| Inventory    | Static document scanning, exact command/dependency references and explicit extraction gaps | [Command extraction](command-extraction.md)         |
| Evidence     | Policy-limited registry/DNS metadata, disclosure boundaries and uncertainty                | [Reference verification](reference-verification.md) |
| Decision     | Versioned action assessment, scoped reviews and non-overridable prohibitions               | [Action assessment](action-assessment.md)           |
| Enforcement  | Controlled execution gate, restricted client profiles and optional Claude Bash quarantine  | [Harness integration](harness-integration.md)       |
| Agent access | Native advisory plugins and local MCP tools for Claude Code, Codex and OpenCode            | [Native plugins](native-plugins.md)                 |

## From evidence to execution

`scan` is a report interface. It does not approve commands found in a document. `assess`
evaluates an exact proposed action: exit `0` means complete/allow, exit `1` means
complete/review or deny, and exit `2` means incomplete/error. Required check failures
never become allow.

Only an enforcing harness in the matching reviewed context can turn an allow into
execution. Reviews bind the action, environment, cwd, isolation profile and input
contents, and expire. The gate revalidates the response and hashes before dispatch;
stale results, changed inputs or incomplete checks withhold execution.

The initial ruleset supports a bounded install subset: pip wheels with automatic
dependency solving disabled, or npm ci with scripts disabled and a supported lockfile.
Unknown syntax, undeclared inputs, prohibited sources and failed mandatory checks cannot
authorize execution. Metadata observations remain separate from operator approval and
malicious-artifact evidence.

## Choose an agent integration

**Native plugins** make scanning available in ordinary coding sessions. They add
setup/status/review workflows and verify a pinned runtime. They do not intercept other
tools, scan every file automatically or install enforcement hooks.

**Protected launchers** remove general native executors and connect protected MCP tools.
Their optional install tool delegates to the operator-configured gate. See
[client integrations](client-integrations.md) for the supported versions and exact
restrictions.

**Custom harnesses** must enforce use at their own tool boundary. A prompt, skill or
voluntarily called MCP scanner cannot prevent an agent using another executor. The
standalone Claude quarantine example denies all matched Bash calls; it is not a general
command allowlist.

## Boundaries and validation

Runtime isolation, secret separation, protected configuration and concurrent-write
controls remain operator responsibilities. The reference gate does not create an OS
sandbox, and client restrictions do not protect a compromised host or client. Publisher
CI helps correct unsafe documentation before publication but does not authorize agent
commands or establish package identity.

Scanner and harness contracts cover bounded parsing, schema errors, timeouts, stale
decisions and changed context. Synthetic executors verify dispatch for a scoped allow
and zero dispatch for withheld actions without installing packages.

Real-client validation separately checks that advisory plugins preserve ordinary tools
and protected launchers block tested native execution paths. See
[native plugin validation](native-plugin-validation.md) and
[protected launcher validation](client-integration-validation.md) for versions,
reproduction commands and limits.
