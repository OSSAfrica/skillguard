# Reference metadata verification

[Documentation](README.md) / Reference metadata verification

Reference verification adds opt-in npm/PyPI metadata observations and optional DNS facts
to the command inventory. It does not install packages, run package-manager commands,
download artifacts or scripts, or certify package legitimacy.

An attacker can register a previously hallucinated package name. The registry will then
correctly report that it exists. SkillGuard therefore always reports package
`identity: "unverified"`; a version pin, repository link, attestation claim, or
successful lookup does not change that field. Execution decisions and harness
enforcement remain work for #184 and #185.

## Explicit operator policy

Ordinary scans remain offline. Both flags are required to enable metadata checks:

```sh
skillguard scan ./llms.txt --format json \
  --verify-references \
  --verification-policy /trusted/config/skillguard-registries.json
```

The policy is a regular JSON file, explicitly selected by the operator, at most 64 KiB,
with schema version 1. It is never auto-discovered inside a scan target. Protect it from
target authors and agent edits; a future harness must supply its trusted configuration
independently of document instructions.

```json
{
  "schema_version": 1,
  "registries": [
    {
      "id": "npm-public",
      "ecosystem": "npm",
      "metadata_url": "https://registry.npmjs.org",
      "install_url": "https://registry.npmjs.org",
      "default": true,
      "packages": ["zod", "@types/node"]
    },
    {
      "id": "pypi-public",
      "ecosystem": "pypi",
      "metadata_url": "https://pypi.org/pypi",
      "install_url": "https://pypi.org/simple",
      "default": true,
      "packages": ["requests", "ruff"]
    }
  ],
  "dns_hosts": ["downloads.example.org"],
  "timeout_seconds": 5,
  "max_requests": 64,
  "cache_ttl_seconds": 300,
  "min_interval_ms": 100
}
```

`metadata_url` is the API base: npm appends an escaped package name; PyPI appends the
normalized name and `/json`. Private registries must expose the corresponding JSON API.
`install_url` identifies the registry/index spelling allowed in an extracted command. It
does not become authorized merely by appearing in a document. There is at most one
policy default per ecosystem; defaults are explicit assumptions for metadata queries,
not a reconstruction of the installation environment.

Each registry requires a `packages` disclosure allowlist. Exact names and glob patterns
such as `company-*` or `@company/*` are supported. `*` explicitly authorizes all names,
including scoped names: use it only when that disclosure is intended. These allowlists
authorize metadata queries, not execution or trust. Python names are normalized by
lowercasing and replacing runs of `.`, `_`, and `-` with `-`. A private name not allowed
at the selected registry is reported as `blocked`; it is never retried against a public
registry.

For a private registry, add a separate entry, its allowed package names, and optionally
`auth_env` naming an operator-provided Bearer-token environment variable. The token is
read only for that configured registry, never from scanned text or `.npmrc`/pip
configuration, and is not included in reports. Other auth schemes and non-JSON private
indexes are not implemented. Credential-bearing, query-bearing, non-HTTPS, or
noncanonical policy URLs are rejected.

Extracted explicit indexes must match configured `install_url` entries. An unknown
index/extra-index blocks that command's metadata routing instead of authorizing a new
destination. Mixed PyPI indexes produce separate attributed observations; installation
precedence and dependency-confusion outcomes are not resolved. Commands with unresolved
wrappers, environment/context overrides, configuration or requirements/constraints
files, `--no-index`, `--find-links`, or unsupported source options cannot silently fall
back to public metadata queries. The effective ambient environment and local
package-manager configuration are not inferred. Unresolved environment, context, or
control-flow constructs conservatively block metadata routing for the document;
duplicate primary index overrides are not guessed.

## Observations, uncertainty, and output

Each analysis result adds `verification`, with `status`, `packages`, `destinations`, and
coverage `gaps`. JSON contains the full observations; text and Markdown summarize them.
Package observations include:

- Ecosystem, normalized package name, requested specifier, configured registry ID,
  metadata URL, source-selection basis, and original source span.
- `state`: `found`, `missing`, `unauthorized`, `rate_limited`, `timeout`,
  `malformed_response`, `unsupported_source`, `unavailable`, `blocked`, `canceled`, or
  `request_limit`.
- `version_state`: `found`, `missing`, `not_requested`, `unsupported_specifier`, or
  `unknown`. Package absence is attributed to the queried endpoint, not labeled a
  confirmed takeover or malware attack.
- Observation/expiry timestamps, cache reuse, and discarded stale evidence.
- Available publication time, a redacted **claimed** repository URL, and provenance
  presence. npm attestation metadata is reported as a claim and never fetched or
  verified. PyPI provenance is not checked.
- Stable signal IDs, explanatory messages, and concrete next steps. Missing pins,
  mutable tags, recent publication within 30 days, and unknown identity are review
  signals, not automatic malware findings. Recency uses registry-supplied times.

The adapters check npm exact semantic versions and named tags, plus Python exact
`==`/`===` requirements. Common stable Python equality normalization (epochs,
leading/trailing zeros, local labels) avoids false absence results. Full range,
prerelease-equivalence, platform, lockfile, and transitive resolution is outside this
stage; unsupported comparisons remain explicit rather than guessed.

There is no bundled malware feed. `malware_check: "not_performed"` is the default. An
internal `Intelligence` interface permits an explicitly configured provider in future
integrations; no provider is auto-loaded by the CLI. A provider's negative match would
still not establish safety.

With verification requested, exit codes are:

| Code | Meaning                                                                                 |
| ---- | --------------------------------------------------------------------------------------- |
| 0    | Score checks pass and the requested observations completed; identity remains unverified |
| 1    | Score failure, missing package/version/tag, or a configured intelligence match          |
| 2    | Input or verification incomplete, unsupported, blocked, canceled, or unavailable        |

Available reports are rendered before observation-related failures are returned.
Existing security scores and per-file `passed` fields are unchanged by metadata checks;
use the separate verification fields. **Exit 0 is not an execution permit.**

## Network and freshness boundaries

All registry endpoints require HTTPS and normal certificate validation. Proxy
environment variables are ignored. Redirects are not followed, including same-host
redirects; a redirect remains an unsupported source. Names are escaped as URL path
components, and metadata/publisher URLs never authorize additional requests.

The transport resolves each new connection, rejects mixed public/private answers by
default, and dials the validated numeric IP without a second hostname lookup. At most 64
answers are accepted per resolution, and every answer is checked before connecting.
Loopback, RFC1918/ULA, link-local, multicast, unspecified, shared/reserved,
documentation, and common address-translation/tunnel ranges are blocked by default.
`allow_private_network: true` permits private/loopback access only for that explicitly
configured registry; link-local metadata services and other reserved ranges remain
blocked. Normal TLS validation still applies. The tests use this exception with local
TLS fixtures and a test CA.

Defaults are 5 seconds per lookup, 64 lookup attempts shared across the scan, a 100 ms
minimum interval, 1 MiB response bodies, and bounded headers. Policy limits cap timeouts
at 30 seconds, attempts at 256, and cache TTL at one hour. Lookups run serially with
context cancellation; DNS checks share the attempt/rate budget. Each document's returned
observations are capped at 512. No automatic retries are implemented by SkillGuard.

The cache is process-local and shared across files in one scan, keyed by registry, name,
and requested specifier. Found/missing snapshots are reusable only before their reported
expiry; negative evidence is capped at 60 seconds. Failed refreshes discard old positive
evidence and report the failure. Errors are not reused as completed checks. There is no
persistent cache of private package metadata.

Destination observations always state ownership as `unverified`, registration
availability as `unknown`, and reachability as `not_checked`. Literal IP scopes can be
identified without network access. DNS is queried only for exact operator-approved
`dns_hosts`; other names are `not_requested`, not assumed resolved. Approved DNS
failures are explicit; NXDOMAIN means `not_found`, not "available to register."
Successful DNS resolution says nothing about ownership, network reachability, content
safety, or package identity. Destination URLs are not fetched.

Primary API references:
[npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md) and
[PyPI JSON API](https://docs.pypi.org/api/json/).
