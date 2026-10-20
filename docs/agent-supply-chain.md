# Agent supply-chain protections

AI-readable documentation is untrusted input even when it is published on a
familiar vendor domain. Install instructions can name nonexistent packages that
someone later registers, or existing packages whose relationship to the project
has never been verified. Pinning and registry existence alone cannot establish
that relationship.

SkillGuard now separates four responsibilities:

| Layer | Delivered behavior | Documentation |
| --- | --- | --- |
| Inventory (#182 / PR #187) | Scan llms text and exact command/dependency references, with explicit extraction gaps | [Command extraction](command-extraction.md) |
| Evidence (#183 / PR #188) | Explicit-policy metadata-only registry/DNS observations; private-name disclosure boundaries and uncertainty | [Reference verification](reference-verification.md) |
| Decision (#184 / PR #189) | Versioned JSON action assessment, reviewed subject/context pairs and non-overridable prohibitions | [Action assessment](action-assessment.md) |
| Enforcement (#185) | Reference controlled execution gate, restrictive Claude Bash quarantine and publisher CI examples | [Harness integration](harness-integration.md) |

The normal `scan` interface remains a report interface. `assess` adds a distinct
contract: exit 0 means complete/allow, exit 1 complete/review-or-deny, and exit 2
incomplete/error. Only an enforcing harness running in the reviewed context can
turn allow into execution. Required-check failure never silently becomes allow.

The initial action ruleset intentionally limits supported installers: pip wheels
with no automatic dependency solving, or npm ci with scripts disabled and a
supported lockfile. Operator reviews bind the exact action, environment, cwd,
profile and input contents, and expire. Unknown syntax, undeclared inputs,
prohibited sources and failed mandatory checks withhold execution. Metadata facts
remain separate from operator approval and malicious-artifact evidence.

No hook, sandbox, schedule, release deployment or local agent configuration is
installed by these changes. Runtime isolation and protection against concurrent
writes remain operator responsibilities. The Claude example blocks every matched
Bash call and is not a general command allowlist. Other tools/hosts need their own
boundaries. Optional future skills or MCP tools can explain these same decisions;
calling a scanner voluntarily does not supply mandatory enforcement.

Validation includes full Go race/regression checks, bounded parser fuzzing,
Windows compilation, static/security checks, and synthetic harness fixtures.
Harness tests assert one dispatch for allow and zero dispatches for review,
denial, malformed/failed scanner output, stale decisions and changed context.
A real-scanner integration test completes scoped review with a fake executor;
no package is installed during those tests.
