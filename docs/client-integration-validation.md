# Installed-client integration validation

Validated on macOS, 20 October 2026:

| Client | Version | Real MCP scan | Real assessment | Forced native executor | Workspace startup override |
| --- | --- | --- | --- | --- | --- |
| Claude Code | 2.1.304 | Received | Partial/review received | Blocked; no marker | Ignored; no marker |
| Codex | 0.163.0 | Received | Partial/review received | Blocked; no marker | Ignored; no marker |
| OpenCode | 2.1.0 | Received | Partial/review received | Shell and Code Mode blocked; no marker | Ignored; no marker |

`integrations/clients/smoke.py` launches each real installed client with its
protected profile against a loopback scripted model. The model requests a scan,
an assessment of an unreviewed package action, and two fabricated executor calls,
even though the executor tools are absent from the advertised tool list. Those
calls could only create a temporary marker if execution escaped the boundary.
The suite asserts receipt of actual MCP tool results, no advertised general
executors, no execution marker, and successful client completion. This avoids
mistaking a client that failed to start for a successful denial test.

Each temporary workspace also contains hostile startup configuration that would
create a separate marker: Claude project hooks/MCP, Codex project MCP, and
OpenCode project permissions/MCP. These configurations did not execute. Codex's
fixture explicitly marks the target trusted to test that boundary.

The model exchanges use synthetic API keys and local providers, with no real
model inference or package installation. Clients still use normal cache/log/auth
storage. The final OpenCode profile isolates global configuration; early discovery
probes loaded unrelated user-configured MCP servers, which motivated this change.
Do not equate the smoke suite with an OS-level network isolation test.

Additional automated contracts cover strict/bounded JSON-RPC, duplicate keys,
unknown fields, tool errors, protected context and policy, source-label redaction,
profile configuration and missing MCP startup. A real Go MCP server invokes the
real Python guard and real assessment engine with a synthetic executable standing
in for pip: unreviewed actions execute zero times, an exact scoped review permits
the fake executable, a changed action is withheld, injected configuration fields
fail, and an altered executable hash withholds execution. No npm/pip process runs.

Run from a reviewed checkout:

```sh
go build -o /tmp/skillguard-clients .
SKILLGUARD_TEST_SCANNER=/tmp/skillguard-clients \
  python3 -I -m unittest discover -s integrations/clients -p 'test_*.py' -v
node --test integrations/clients/opencode-plugin/test.mjs
python3 -I integrations/clients/smoke.py --scanner /tmp/skillguard-clients
```

Use `--client claude`, `--client codex` or `--client opencode` to select a client.
The installed-client suite is opt-in and requires the pinned clients. Standard
CI runs the MCP, profile and synthetic gate tests without installed AI clients.

These results establish the tested tool paths and configurations, not universal
protection across releases or arbitrary plugins. Retest after upgrades, before
changing permissions and before adding another executor. Real isolated package
installation and interactive UI behavior are outside this validation record.
