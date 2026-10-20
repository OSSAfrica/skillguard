# Policy reference

[Documentation](README.md) / Policy reference

A policy is operator-controlled JSON that defines which checks and sources SkillGuard
may use. You choose the file explicitly. Keep it outside the target project and protect
it from agent writes, including writes through its parent directories.

## Choose the right policy

| Task                                       | Policy                                                           | Command                                                                                             |
| ------------------------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Static document scanning                   | None                                                             | `skillguard scan ./llms.txt`                                                                        |
| Registry/DNS metadata checks during a scan | Verification policy                                              | `skillguard scan ./llms.txt --verify-references --verification-policy /protected/verification.json` |
| Assessment of an exact proposed install    | Assessment policy, with a nested verification policy when needed | `skillguard assess --policy /protected/assessment.json < request.json`                              |

The two policy files have different top-level fields. For `assess`, put registry
configuration inside `verification`. For `scan`, use the verification object itself as
the whole file. Neither file installs hooks, creates a sandbox or executes commands.

The tables mark fields as required by the policy contract. Supply required fields
explicitly; use `[]` for empty required lists, not `null`. Optional fields list their
behavior when omitted. JSON comments and unknown fields are unsupported.

## Assessment policy

See the [assessment schema](schemas/action-policy.v1.json) and
[restrictive starting example](examples/policies/assessment.json).

| Field                        | Required / default                                                           | Meaning and accepted values                                                                                                                                                                                                               |
| ---------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version`             | Required                                                                     | Integer `1`. Selects the JSON format; this is separate from your policy revision and the installed engine version.                                                                                                                        |
| `id`                         | Required                                                                     | Your policy's identifier, such as `company-install-policy`. Appears as `policy_id` in responses. Use the assessment identifier format below.                                                                                              |
| `version`                    | Required                                                                     | Your policy revision as a string, such as `"1"`. Appears as `policy_version`; SkillGuard does not resolve or order revisions for you. Uses the assessment identifier format.                                                              |
| `max_age_seconds`            | Required                                                                     | Integer `1`–`300`. Upper bound on an assessment's lifetime after `assessed_at`. Review or evidence expiry can shorten it; partial/error assessments expire immediately. `0` is invalid.                                                   |
| `isolated_profiles`          | Required; `[]` is valid                                                      | Up to 32 profile identifiers the operator attests to enforcing. The request's `context_profile` must match one. Empty means no verified profile, so assessment cannot allow execution. Naming a profile does not create isolation.        |
| `reviewed_actions`           | Required; `[]` is valid                                                      | Up to 256 exact action/context review records. See the review table below. An empty list grants no reviews.                                                                                                                               |
| `prohibited_packages`        | Optional; no package prohibitions                                            | Up to 256 ecosystem/name rules, optionally limited to a version. A match produces deny. Reviews cannot override it.                                                                                                                       |
| `prohibited_artifact_hashes` | Optional; no artifact prohibitions                                           | Up to 256 exact artifact digests: `sha256:` plus 64 lowercase hexadecimal characters, or `sha512-` plus canonical Base64 encoding of 64 bytes. A matching resolved artifact produces deny. This list does not fetch or inspect artifacts. |
| `require_metadata`           | Required; no implicit choice                                                 | Boolean. `true` requires complete, fresh exact-version registry observations and a `verification` object. `false` selects offline assessment; source, isolation, input, prohibition and review requirements remain.                       |
| `verification`               | Required when `require_metadata` is `true`; otherwise optional in the schema | The verification policy described below. It also declares allowed effective registry sources, so supported registry installs still need matching entries in offline mode. Omitting it is not an unrestricted-source policy.               |

**Assessment identifier format:** 1–128 ASCII characters, starting with a letter or
digit, followed by letters, digits, `_`, `.`, `:`, or `-`. This applies to `id`,
`version`, profile identifiers and `review_id`.

The engine evaluates a fixed action ruleset. There is no policy field to waive required
static checks, authorize arbitrary shell execution, enable install scripts or approve an
entire package ecosystem. Metadata existence and package disclosure lists do not replace
review.

### Review records: `reviewed_actions[]`

| Field                      | Required / default | Meaning and accepted values                                                                                                                                                                                                         |
| -------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `subject_fingerprint`      | Required           | `sha256:` plus 64 lowercase hexadecimal characters. Copy the fingerprint from assessment of the exact action the operator reviewed; argv order and shell text belong to the subject.                                                |
| `context_fingerprint`      | Required           | The assessment's context fingerprint in the same SHA-256 format. Binds declared and resolved target/cwd, exact environment, profile and declared input contents. Another action context needs its own review.                       |
| `review_id`                | Required           | An operator-assigned audit reference using the assessment identifier format, such as `change-1234`. It is not an approval token by itself.                                                                                          |
| `expires_at`               | Required           | A nonzero RFC 3339 timestamp. Write UTC with `Z`, such as `2026-10-21T12:00:00Z`. A record matches only before expiry; an expired record grants no review.                                                                          |
| `accept_mutable_artifacts` | Optional; `false`  | Boolean. `true` accepts unresolved artifact bytes for this exact reviewed subject/context, such as a direct version without enforced hashes. It does not disable other checks or establish safety. Prefer enforced artifact hashes. |

An operator must review the action and actual context independently of the model. Use
the assessment response's fingerprints; do not invent or approximate them. For the
reference gate, obtain the report with `guard.py --assess-only` so the reviewed context
includes the gate's executable bindings. See the
[harness review procedure](harness-integration.md#install-check-review-and-remove).

Reassess after adding a review. The gate must still validate the fresh response and
recheck hashes before execution. Changing the command, inputs, environment or runtime
can invalidate the review. Changing policy contents changes `policy_fingerprint` even if
you keep the same policy revision string.

### Package prohibitions: `prohibited_packages[]`

| Field       | Required / default                           | Meaning and accepted values                                                                                                                                                                                                                                                |
| ----------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ecosystem` | Required                                     | `npm` or `pypi`. Selects name/version matching rules.                                                                                                                                                                                                                      |
| `name`      | Required                                     | Exact package name, 1–214 characters; this is not a glob. npm names compare exactly. PyPI matching lowercases names and collapses runs of `.`, `_` and `-` to `-`.                                                                                                         |
| `version`   | Optional; omitted or `""` means all versions | A string up to 128 characters. For npm, canonical numeric `major.minor.patch`. For PyPI, one to four dot-separated numeric components; matching normalizes leading zeros and trailing zero padding, so `1.0` matches `1.0.0`. Ranges and prerelease forms are unsupported. |

Example prohibition list:

```json
{
  "prohibited_packages": [
    { "ecosystem": "npm", "name": "example-blocked-package" },
    { "ecosystem": "pypi", "name": "example-blocked-library", "version": "1.0" }
  ]
}
```

This fragment belongs inside an assessment policy. It is not a complete policy or a
claim that those illustrative names identify malware.

## Verification policy

Use this object as the complete `scan --verification-policy` file, or nest it inside an
assessment policy's `verification` field. See the
[standalone example](examples/policies/verification.json).

| Field               | Required / default                      | Meaning and accepted values                                                                                                                                                                                                                                                               |
| ------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version`    | Required                                | Integer `1`.                                                                                                                                                                                                                                                                              |
| `registries`        | Required by the contract; `[]` is valid | Up to 16 registry definitions. No entries means no configured package metadata destination. Each entry has its own ecosystem, URLs and disclosure list.                                                                                                                                   |
| `dns_hosts`         | Optional; `[]`                          | Up to 128 exact hostnames, each at most 253 characters, permitted for destination DNS checks. No URL, port or wildcard. Names are lowercased and a final dot is removed. An omitted host gets `not_requested`; no destination content is fetched and resolution does not prove ownership. |
| `timeout_seconds`   | Optional; `5`                           | Per-lookup timeout. Integer `1`–`30`, or `0` to select the default.                                                                                                                                                                                                                       |
| `max_requests`      | Optional; `64`                          | Shared lookup-attempt budget across the verifier's scan, including approved destination DNS checks. Integer `1`–`256`, or `0` for the default. Exhaustion reports incomplete coverage.                                                                                                    |
| `cache_ttl_seconds` | Optional; `300`                         | Maximum process-local reuse lifetime for package observations. Integer `1`–`3600`, or `0` for the default. Negative observations are additionally capped at 60 seconds. There is no persistent metadata cache.                                                                            |
| `min_interval_ms`   | Optional; `100`                         | Minimum spacing between lookup attempts in milliseconds. Integer `1`–`10000`, or `0` for the default.                                                                                                                                                                                     |

For these four numeric settings, **zero means default**, not unlimited requests, no
cache, no delay or no timeout. Negative and above-limit values are invalid. Lookups run
serially without automatic retries. Fixed response/header limits also apply; policy does
not expose fields to remove them.

### Registry entries: `registries[]`

| Field                   | Required / default        | Meaning and accepted values                                                                                                                                                                                                                                                                                                         |
| ----------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                    | Required                  | Unique registry label, 1–128 ASCII characters: start with a letter or `_`, then letters, digits, `_` or `-`. This format differs from assessment identifiers.                                                                                                                                                                       |
| `ecosystem`             | Required                  | `npm` or `pypi`. Selects metadata API and package-name handling.                                                                                                                                                                                                                                                                    |
| `metadata_url`          | Required                  | Canonical HTTPS API base, at most 512 characters. npm appends the escaped package name; PyPI appends the normalized name and `/json`. Examples: `https://registry.npmjs.org` and `https://pypi.org/pypi`.                                                                                                                           |
| `install_url`           | Required                  | Canonical HTTPS registry/index base permitted in an extracted install command, at most 512 characters. PyPI commonly uses `https://pypi.org/simple`. The same ecosystem/install URL cannot appear twice.                                                                                                                            |
| `default`               | Optional; `false`         | Boolean. At most one default per ecosystem. Lets document metadata checks select a registry when the command has no explicit source; it does not reconstruct the environment. Assessment still requires its supported explicit source flags.                                                                                        |
| `packages`              | Required; nonempty        | 1–256 permitted package-name patterns, each up to 256 characters. Allows disclosure of these names to this registry's metadata API. Use exact names or `*` patterns such as `company-*` or `@company/*`; `?`, bracket patterns and backslashes are rejected. The special pattern `*` permits all names, including scoped npm names. |
| `auth_env`              | Optional; no Bearer token | Name of an operator-provided environment variable holding this registry's Bearer token. Use a letter or `_`, followed by letters, digits or `_`, up to 128 characters. Store the variable name here, not the token. A missing, empty or invalid configured token reports `unauthorized`.                                            |
| `allow_private_network` | Optional; `false`         | Boolean. `true` permits private/loopback destinations for this registry only. It does not permit link-local metadata services or other prohibited reserved addresses, or disable TLS validation.                                                                                                                                    |

Endpoint URLs cannot contain credentials, queries, fragments, encoded/noncanonical paths
or non-HTTPS schemes. The loader normalizes host case and trailing slashes. Private
registries must implement the corresponding npm/PyPI JSON metadata API; other
authentication schemes and arbitrary private index formats are unsupported.

For PyPI, package disclosure matching also lowercases names/patterns and collapses runs
of `.`, `_` and `-` to `-`. Names outside the selected registry's disclosure list are
blocked, not retried against a public registry. These lists authorize queries, not
installation or package legitimacy. See
[verification boundaries](reference-verification.md#network-and-freshness-boundaries).

## Starting examples and review workflow

The [assessment example](examples/policies/assessment.json) enables required metadata
checks for explicitly listed names but has **no isolated profiles and no reviews**. It
is a restrictive starting point, not a ready-to-execute approval. The
[verification example](examples/policies/verification.json) permits metadata queries for
`zod` and `requests` at their specified public registries. Review these name disclosures
before using it with private documentation.

From a reviewed checkout, copy the example you need to a protected location outside your
target. For example, if your target is a project directory rather than your home:

```sh
mkdir -p "$HOME/.config/skillguard"
cp docs/examples/policies/assessment.json "$HOME/.config/skillguard/assessment.json"
```

Edit the file as an operator. Protect it and its parent directories from agent writes;
being outside the target is not itself an access-control mechanism. The assessment
loader resolves symlinks and rejects policy paths inside the target tree. Standalone
verification policy loading does not enforce that containment check.

For document metadata checks, save the verification example separately and run:

```sh
skillguard scan ./llms.txt --verify-references \
  --verification-policy /protected/verification.json
```

For assessment, supply a [request](action-assessment.md#request-and-trust-boundary)
using the actual target, cwd, environment, profile and dependency input inventory:

```sh
skillguard assess --policy "$HOME/.config/skillguard/assessment.json" < request.json
```

Then follow the operator workflow:

1. Configure and verify real isolation and the protected runtime before adding its
   profile ID. A profile entry is an attestation of those controls, not their setup.
2. Assess the exact action and context. A missing profile gives partial coverage; an
   unreviewed action needs review even when the package exists.
3. Resolve gaps and review the action, inputs and artifacts independently. Add only the
   matching fingerprint pair, review ID and expiry; prefer enforced hashes.
4. Reassess through the same controlled gate. Execute only after the gate validates a
   fresh complete allow and rechecks bindings. Errors, partial coverage, review, deny
   and changed inputs withhold execution.

The CLI has no policy initialization wizard or automatic approval command. A policy file
alone neither intercepts agent tools nor provides isolation. See
[action assessment](action-assessment.md) for decisions and exit codes and
[harness integration](harness-integration.md) for enforcement.

## File limits and implementation references

A standalone verification policy must be a regular JSON file no larger than 64 KiB. An
assessment policy, including its nested verification object, is bounded to 1 MiB. Both
loaders reject unknown fields and extra JSON values; the assessment loader also rejects
duplicate keys. The schema describes the wire contract, and runtime validation adds
identifier, URL and semantic checks.

Maintainers should check changes against:

- [Assessment loading and validation](../internal/assess/json.go).
- [Assessment decisions and expiry](../internal/assess/evaluate.go).
- [Verification fields, defaults and validation](../internal/verify/policy.go).
- [Verification routing and caching](../internal/verify/verify.go).
