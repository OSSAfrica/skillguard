# Action assessment v1

[Documentation](README.md) / Action assessment v1

For each policy field, its default and accepted values, see the
[policy reference](policies.md).

`skillguard assess --policy /protected/operator.json < request.json` evaluates one exact
proposed install action. It never runs that action or installs anything. This interface
is separate from `scan` and has its own output and exit contract. There is no score
threshold in an action assessment.

The result is one JSON object on stdout, including request, policy and flag errors.
Diagnostics belong on stderr. Help/version requests are ordinary CLI help, not
assessments. A consumer must validate the response schema, status, decision, freshness
and bindings, as well as the process exit code:

| Exit | Meaning                                                       | Execute?                                  |
| ---- | ------------------------------------------------------------- | ----------------------------------------- |
| 0    | `complete` and `allow`                                        | Only within the matching enforced context |
| 1    | Complete `review` or `deny`                                   | No                                        |
| 2    | `partial`, `error`, malformed input or required-check failure | No                                        |

An `allow` is a conditional policy result, not proof that code is safe. The separate
[harness integration](harness-integration.md) provides enforcement at the tool boundary.
Installing this CLI alone does not intercept agent tools.

## Request and trust boundary

See the [request schema](schemas/action-request.v1.json),
[policy schema](schemas/action-policy.v1.json), and
[response schema](schemas/action-response.v1.json). JSON Schema describes the wire
format; semantic checks additionally enforce canonical local paths, source rules and
bounded parsing. Duplicate keys, unknown fields, extra JSON values, invalid UTF-8 and
oversized requests are rejected. Errors use fixed messages rather than echoing
attacker-controlled command arguments or parser errors.

```json
{
  "schema_version": 1,
  "target_root": "/workspace/project",
  "cwd": "/workspace/project",
  "action": {
    "mode": "argv",
    "argv": [
      "pip",
      "install",
      "--only-binary=:all:",
      "--no-deps",
      "--require-hashes",
      "--index-url",
      "https://pypi.org/simple",
      "-r",
      "requirements.txt"
    ]
  },
  "environment": {},
  "context_profile": "isolated-installer-v1",
  "inputs": [{ "path": "requirements.txt", "kind": "requirements" }],
  "provenance": ["https://vendor.example/llms.txt"]
}
```

The **trusted harness**, not the model, must supply the real target root, cwd,
argv/shell text, complete execution environment, profile and dependency/config input
inventory. `environment` means the exact environment used for execution, not a delta to
inherit over a parent process. `provenance` is optional display context; it never grants
access, substitutes for the action, or approves it. A raw Bash action uses
`{"mode":"bash","command":"..."}`. Only one foreground simple command with literal
arguments can be completely assessed. Expansion, wrappers, chaining, background
execution, redirects, control flow and unknown options withhold permission. Direct
package execution and remote downloads are prohibited by this install-only ruleset.

The operator selects a policy file explicitly, outside `target_root`, including when cwd
is a subdirectory. Symlinks are resolved for this check. The target/model must not be
able to edit policy, select a different policy, shrink `target_root`, or change the
request after assessment. Filesystem containment alone does not establish ownership or
protect a writable parent directory: those controls belong to the harness/operator. No
policy is discovered in repository content, and no repository suppression or document
instruction can waive mandatory rules.

## Supported resolution

Input paths are canonical local paths relative to cwd, explicitly listed by the harness.
Reads use `os.Root`, reject escaping symlinks and non-regular files, and are bounded to
32 files, 1 MiB each, 4 MiB total and 512 dependency entries. Raw contents and raw
command/environment values are not echoed. Findings expose bounded dependency facts,
locations and file hashes as **untrusted data**.

- **pip install:** requires `--only-binary=:all:`, `--no-deps` and one explicit
  configured `--index-url`. Direct registry requirements and flat `-r` files support
  exact numeric stable `==` versions. A requirements file can use continued lines and
  SHA-256 hashes; hashes count as enforced artifact bindings only with
  `--require-hashes`. Includes, constraints, markers, extras, editable/direct/Git/local
  dependencies, arbitrary options and full dependency solving are unsupported or
  prohibited.
- **npm ci:** requires `--ignore-scripts`, one explicit configured `--registry`, and
  declared `package.json` plus package-lock v3. The engine compares root declarations,
  inventories all installed registry entries (including optional entries), requires
  SHA-512 integrity, and checks artifact registry origins. Workspaces, overrides,
  bundled/link entries, shrinkwrap precedence, other lock versions and implicit
  `npm install` resolution cannot produce an allow.
- **Configuration:** known cwd installation files are checked for undeclared presence.
  Declared `.npmrc`/`pip.conf`/`pip.ini` support only registry/index settings and
  comments; unresolved authentication, scopes, proxies or other settings withhold
  permission. Config files cannot supply a missing explicit command source.
  Source-changing/interpreter environment overrides also withhold permission. External
  configuration is addressed by the isolated execution profile below, not silently
  assumed absent.

For v1, exact versions intentionally use a narrow numeric grammar. This can require
review or report partial coverage for valid package-manager syntax. Unsupported cases
are not a clean bill of health. Sources with redacted URL components cannot be
authorized from sanitized evidence.

## Operator review and isolated profiles

A policy starts with no reviewed actions:

```json
{
  "schema_version": 1,
  "id": "company-install-policy",
  "version": "1",
  "max_age_seconds": 60,
  "isolated_profiles": [],
  "reviewed_actions": [],
  "require_metadata": true,
  "verification": {
    "schema_version": 1,
    "registries": [
      {
        "id": "pypi",
        "ecosystem": "pypi",
        "metadata_url": "https://pypi.org/pypi",
        "install_url": "https://pypi.org/simple",
        "packages": ["requests"]
      }
    ]
  }
}
```

A profile ID is an **operator attestation**, not an isolation mechanism. Before adding
`isolated-installer-v1` to `isolated_profiles`, the harness must enforce:

1. Trusted package-manager/interpreter binaries and executable lookup; no
   target-controlled startup modules, shell configuration or executable shims.
2. The exact supplied environment and cwd; no inherited hidden environment.
3. No undeclared external package-manager configuration, parent configuration,
   interpreter/site customization or mutable installed context that changes resolution.
   Only explicitly inventoried inputs influence the install.
4. Protection of policy, binaries, input contents and execution context between
   assessment and execution, including filesystem and network isolation as required by
   the operator's installer configuration.

If a harness cannot uphold this contract, it must not claim this profile. No matching
profile means partial coverage and exit 2. This intentionally prevents an ordinary
unsandboxed model chat from manufacturing an executable allow by claiming a clean
documentation scan.

An independent operator reviews the actual command, complete dependency set, artifact
digests, project identity and inputs. The operator can then add a `reviewed_actions`
entry with the response's `subject_fingerprint`, `context_fingerprint`, a `review_id`,
and UTC `expires_at`. There is no automatic “approve this report” command. Review
records expire and cannot override denied sources, prohibited packages/hashes, scripts,
unsupported syntax or failed checks. An unreviewed dependency/action returns review even
when registry metadata exists.

Unhashed direct versions remain mutable artifact selections. They require an explicit
`accept_mutable_artifacts: true` in that exact review record; the default withholds
allow. This records a deliberate operator acceptance of unresolved artifact bytes, not
evidence of safety. Prefer enforced lock/requirements hashes. A digest proves byte
identity, not that those bytes are benign. Source builds and their unresolved build
dependencies are prohibited; pip actions require wheels only.

`prohibited_packages` entries match ecosystem/name and optionally version; Python names
normalize case and runs of dash/underscore/dot. Numeric release versions compare with
PEP 440 zero padding (`1.0` equals `1.0.0`), including leading-zero normalization. npm
exact versions require canonical `major.minor.patch`; shorthands such as `1.0` are
ranges and cannot pass the exact-version rule. Version-specific prohibitions accept only
these supported numeric forms. No version means all versions.
`prohibited_artifact_hashes` uses `sha256:<hex>` or `sha512-<base64>`. These are
operator prohibitions, not inferred malware labels. Confirmed malware from a trusted
embedded intelligence provider returns `SG_MALWARE_CONFIRMED` and deny. No CLI
intelligence feed is implicitly enabled.

## Metadata, uncertainty and binding

`require_metadata: true` requires complete exact-version observations using the embedded
verification policy and its explicit name disclosure lists. Network checks are withheld
if static context is unresolved or a prohibition already applies. Errors, stale
evidence, missing observations or unsupported versions cannot produce allow. Missing
packages/versions produce deny; this does not claim that a missing name is malware.
Publication age and identity remain facts, separate from the deterministic action
policy. Existence never approves an action.

`require_metadata: false` is an explicit offline mode. The response records
`registry_metadata` as optional/not_requested; operator review, prohibitions and static
input/context checks still apply. Registry policy still identifies the allowed effective
sources. Verification package disclosure lists are not execution allowlists; reviewed
exact actions govern execution.

Bindings are SHA-256 over Go's canonical `encoding/json` representation:

- `subject_fingerprint`: exact Action object, including mode and argv/text.
- `context_fingerprint`: declared/real root and cwd, exact environment, profile, sorted
  input paths/kinds/status/content hashes.
- `policy_fingerprint`: complete protected policy, including review records.
- `evidence_fingerprint`: resolved dependency/artifact facts and registry evidence.
- `decision_fingerprint`: the response with an empty decision fingerprint.

These are integrity identifiers, not signatures or bearer approval tokens. A harness
should reassess immediately before execution, compare the action/context it will
actually use, reject expired or malformed results, and prevent changes between checking
and using inputs. Do not reimplement the context hash from an approximation. Fresh
assessment is the supported reuse check. Validity is bounded by the policy's
1–300-second age limit, review expiry, and metadata expiry; partial/error responses are
immediately expired. Mutable registries, DNS, installer artifacts and a changed
executable cannot be frozen by a JSON digest. A remote consumer needs an authenticated
transport or signed envelope separately.

## Stable rules and examples

Rules have stable IDs and fixed remediation text. Key IDs include `SG_REVIEW_REQUIRED`,
`SG_CONTEXT_UNVERIFIED`, `SG_ACTION_UNSUPPORTED`, `SG_INPUT_UNDECLARED`,
`SG_INPUT_UNAVAILABLE`, `SG_SOURCE_UNRESOLVED`, `SG_SOURCE_PROHIBITED`,
`SG_VERSION_UNPINNED`, `SG_ARTIFACT_UNBOUND`, `SG_PACKAGE_PROHIBITED`,
`SG_ARTIFACT_PROHIBITED`, `SG_INSTALL_SCRIPTS`, `SG_REFERENCE_MISSING`,
`SG_METADATA_INCOMPLETE`, `SG_METADATA_STALE`, and `SG_MALWARE_CONFIRMED`. Facts keep
their own input locations; action-level rules point to `action` line 1. `checks`
identifies required coverage separately from decision rules. A deny can coexist with
partial coverage (exit 2 still wins).

[Examples](examples/assessment/) show request/policy and allow, review, deny, partial
and error response shapes. Their hashes/review IDs are illustrative; copying an example
response is never authorization for an action.
