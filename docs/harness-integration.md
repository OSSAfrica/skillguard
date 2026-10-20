# Enforcing SkillGuard decisions in a coding harness

The [action contract](action-assessment.md) is a decision engine. Enforcement
must live at the tool boundary, outside model-controlled prompts and files.
This phase provides two deliberately scoped reference integrations:

| Integration | Coverage | Behavior |
| --- | --- | --- |
| Python synchronous custom tool boundary | Only calls dispatched through `guard.py` | Assess each exact argv install, validate allow, check context, execute once |
| Claude Code PreToolUse quarantine | All matched Bash tool calls | Deny Bash and direct users to the controlled tool |

The custom boundary requires Python 3.10+ and an **operator-provided isolated
runtime** satisfying the action profile contract. It does not create a sandbox.
Do not add a profile merely to make a scan pass. The Claude hook deliberately
cannot authorize Bash: its payload does not attest a complete future execution
environment or protect files between hook return and tool execution.

## Controlled execution path

The harness exposes a synchronous install tool implemented by
[`examples/harness/guard.py`](../examples/harness/guard.py), with input:

```json
{
  "mode": "argv",
  "argv": ["pip", "install", "--only-binary=:all:", "--no-deps", "--require-hashes", "--index-url", "https://pypi.org/simple", "-r", "requirements.txt"]
}
```

The agent cannot supply cwd, policy, environment, profile, executable mapping or
input permissions. Protected operator configuration supplies them. Executables,
scanner and adapter configuration are hash-bound; their hashes also enter the
actual execution environment and therefore the assessment's context fingerprint.
The gate accepts only mapped pip/pip3/npm argv actions. `bash -c`, raw shell
commands, extra fields and unregistered tools are withheld. Agent-generated
commands require no source/documentation attribution.

For each call, the adapter:

1. Snapshots protected configuration/policy/scanner/executables and declared
   input hashes. It never discovers policy inside the target.
2. Sends the exact action and operator context to the scanner with a 20-second
   timeout. No harness environment or scanner authentication secrets are inherited.
3. Requires exit 0, schema/ruleset v1, complete/allow, matching subject digest,
   complete required checks, current timestamps, a review ID, response digest,
   bindings and matching input inventory.
4. Compares the snapshot again and checks freshness immediately before one
   `subprocess.run` dispatch with an explicit executable, cwd and exact environment.
   It never invokes a shell. Installer output goes to stderr; the tool reply is JSON.

Review, deny, partial, error, absent scanner, timeout, crash, malformed/duplicate
JSON, stale or wrong-subject output and changed inputs/configuration execute zero
times. Responses identify a fixed reason and next step without echoing secrets.
A scoped operator review changes the protected policy; the model cannot answer
its own review request. Every subsequent call is assessed again. There is no
cache of executable approvals, blanket disable switch or stale “scan passed” token.

The real runtime must freeze/protect relevant files and executable resolution
between assessment and dispatch. Snapshot comparisons detect changes but do not
provide an atomic filesystem transaction; a concurrent writer can race them.
Only deploy this path where the operator profile enforces the documented isolation,
trusted interpreter/startup state, configuration boundaries and no concurrent
mutation during check/use. Registry bytes and network routing remain mutable;
prefer enforced artifact hashes. This reference cannot protect an unrestricted
host or alternate execution/network/MCP tools the agent can still access.

## Install, check, review and remove

1. Build and review SkillGuard and this adapter. Copy the scanner, `guard.py`,
   Python runtime and package-manager runtime to protected locations outside the
   target. Deny agent writes to those files, their parent directories and policy.
   Pin the reviewed scanner and package-manager SHA-256 values in
   [`operator-config.example.json`](../examples/harness/operator-config.example.json).
2. Configure the real isolated runtime, then configure its profile ID in both
   the protected action policy and adapter configuration. Provide the exact
   environment, cwd, target root and permitted input inventory. No profile
   configuration here creates or verifies a container/OS sandbox automatically.
3. Connect the harness's install-tool callback to this command, using structured
   stdin rather than interpolating arguments into a shell:

   ```sh
   /protected/python3 -I /protected/skillguard/guard.py --config /protected/adapter.json
   ```

4. Check configuration without executing an install:

   ```sh
   /protected/python3 -I /protected/skillguard/guard.py --config /protected/adapter.json --check
   python3 -I -m unittest discover -s examples/harness -p 'test_*.py' -v
   ```

   `--check` validates file locations and hashes, not isolation or approval. Run
   denial/timeout/missing-scanner probes in the actual harness and verify that
   executor counters remain zero before allowing agent access. Fixtures use
   synthetic names and fake executors, never install malware or packages.
5. An initial action returns withheld/review. The operator uses `guard.py --config /protected/adapter.json --assess-only`
   with the same stdin action to obtain a fresh report using the **same
   adapter-generated context**, including both `SKILLGUARD_*_SHA256` entries.
   This reporting mode never executes; it returns `assessed_only` and embeds
   the scanner exit code and report. The operator independently reviews the
   command/artifacts/inputs, and adds only that subject/context pair to
   `reviewed_actions` with an expiry and review ID. Configuration and executable
   hash changes require another review. See the contract for mutable-artifact
   acceptance and why copying a previous report is not approval.
6. To remove the integration, disable the custom install tool in the harness,
   remove its callback/configuration, then remove protected adapter files when
   no tool is using them. Restore another enforcement boundary before exposing
   unrestricted execution. Nothing in this repository automatically installs
   hooks, changes your local harness, or creates hosted schedules.

`guarded_run` accepts scanner/executor callbacks for embedding/tests. Those are
trusted harness interfaces, never model-selectable tools. The CLI's protected
configuration is the reference deployment; direct library callers must uphold
its trust boundaries. Missing input permissions fail closed; they do not trigger
recursive reads of arbitrary files.

## Claude Code quarantine

The optional
[`claude-settings.json`](../examples/harness/claude-settings.json) targets
Claude Code **v2.1.295+**, whose official
[hooks reference](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails)
documents `onFailure: "block"`. It denies **all** Bash calls, including harmless
commands, rather than trying to recognize installers with a bypassable regex.
Its `PreToolUse` response follows the official
[decision-control format](https://code.claude.com/docs/en/hooks#pretooluse-decision-control).
The custom install path remains a separate operator-controlled tool.

Copy the quarantine script to a protected location and merge the example into
operator-managed Claude settings, replacing the absolute Python/script paths.
Use the full `Bash` matcher, synchronous hook, exec-form arguments, timeout and
`onFailure: "block"` as shown. Older clients lack the documented failure guarantee;
do not describe them as supported by this example. Test malformed events,
missing scripts, unavailable interpreters and timeouts through the real client;
every matched Bash attempt must remain blocked.

The hook returns a fixed denial even for malformed/unknown payloads. It never
turns hook metadata, a model-provided scan, or a human permission prompt into an
allow. To uninstall, remove its exact hook entry from protected settings and
restart/reload according to Claude's settings behavior, then remove the script.
This only covers matched Bash calls. Other shells, execution MCPs, SDK tools,
remote hosts, network tools, disabled hooks or modified settings are outside
coverage and must be disabled or independently gated by the operator. An optional
MCP scanner/skill can explain decisions, but cannot replace interception.

## Publisher CI

[`examples/publisher-ci`](../examples/publisher-ci/) complements agent-side gates:
a publisher scans its llms documentation before publishing and periodically
rechecks explicitly permitted registry references. A missing package is an
unresolved reference to correct, not proof that someone exploited a company.
Publisher scanning does not authorize agent commands, prove package identity,
review artifacts, or establish domain ownership.
