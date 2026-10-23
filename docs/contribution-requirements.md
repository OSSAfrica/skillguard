# Contribution requirements audit

[Documentation](README.md) / Contribution requirements audit

Checked on **20 October 2026** against the repository's live settings, effective `main`
rules, PR #201 checks and tracked workflows. This record explains the corrections in
[Contributing](../CONTRIBUTING.md); the live merge box remains authoritative when
settings change.

## Effective merge gates

Classic branch protection and the active
[Main Protection ruleset](https://github.com/OSSAfrica/skillguard/rules/15202241) apply
together. Reading only one misses requirements from the other.

| Area                     | Verified setting                                                                                       | Documentation implication                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| Target                   | Default branch is `main`; the ruleset targets the default branch                                       | Ordinary PRs target `main`. There is no current `release` branch in the repository.                                       |
| Reviews                  | Both layers require one approval; classic protection dismisses stale approvals                         | New commits can require a fresh qualifying approval.                                                                      |
| Unattributed Copilot PRs | `require_extra_approval_for_unattributed_changes: true`                                                | One additional approval applies to Copilot PRs not attributed to a person. With the current count, these need two.        |
| Status checks            | Classic protection names `test` and `build`, from GitHub Actions, with `strict: true`                  | Both must pass on an up-to-date branch. Rebasing is not the only permitted way to update it.                              |
| Signatures               | Active ruleset has `required_signatures`; the classic signature flag is false                          | Verified signatures are enforced through the ruleset. GPG is supported, alongside GitHub-supported SSH/S/MIME signatures. |
| Code scanning            | Required tool is CodeQL; `high_or_higher` security threshold and `errors_and_warnings` alert threshold | Required analysis must exist and blocking findings must be resolved. Green build/test jobs alone are insufficient.        |
| Code Quality             | Active rule uses severity `errors`                                                                     | Required quality analysis must meet that threshold.                                                                       |
| Branch integrity         | Force pushes and branch deletion are blocked on `main`                                                 | Contributors work on branches and submit PRs.                                                                             |
| Merge methods            | Repository and ruleset permit merge, squash and rebase; linear history is not required                 | The guide must not claim rebase-only history. Maintainers choose a compliant method.                                      |
| Admin treatment          | Classic protection includes administrators; the ruleset lists an organization-admin bypass             | A bypass capability exists, but it is not the normal contributor workflow or a replacement for review.                    |

No CODEOWNERS file was found at the conventional root, `.github/` or `docs/` locations,
and neither protection layer requires owner approval or last-push approval. Required
conversation resolution is also disabled. The guide still asks contributors to address
review feedback, without presenting these disabled options as automatic merge gates. The
separate automatic Copilot-review ruleset is disabled; it does not replace the active
Code Quality requirement or qualifying reviewer approval.

## DCO: required contribution policy, incomplete status enforcement

The repository enables web-based commit sign-off and reports a `DCO` check on PRs. No
`.github/dco.yml`, `.github/dco.yaml` or root `.dco.yml` configuration was found; in
particular, individual/third-party remediation support is not enabled by a tracked
repository configuration.

**The named required status contexts currently contain only `test` and `build`.** DCO is
not in that list or a required-status rule in the effective ruleset. A passing DCO check
remains a contribution requirement in the guide, but that requirement is not fully
represented in the status-check configuration.

Adding `DCO` as a required status check is a separate repository configuration decision.
This documentation change does not modify protection settings. Maintainers should check
DCO explicitly before merging while that configuration gap remains.

DCO and cryptographic signing are separate: lowercase `-s` adds the trailer; uppercase
`-S` signs the commit. Neither repairs earlier commits. The guide now explains both,
GitHub verification, author identity and ways to repair a contributor's own commits.

## Automated validation inventory

| Source                                                                                                                                      | Runs / coverage                                                                                                                                                                    | Contributor guidance                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CI workflow](../.github/workflows/ci.yml)                                                                                                  | PRs to `main`; Go race/coverage tests, harness/client Python tests, OpenCode Node tests, native plugin Python/Node contracts, go vet, golangci-lint and gosec; dependent build job | Go tests alone do not reproduce the required `test` check. Supply the scanner environment variable for real gate integration cases.                            |
| [CodeQL workflow](../.github/workflows/codeql.yml)                                                                                          | Go and GitHub Actions analysis for PRs to `main`, plus push/schedule runs                                                                                                          | Fork runs can wait for maintainer approval. Required analysis cannot be treated as optional because a run is pending.                                          |
| GitHub-managed Code Quality                                                                                                                 | Recent PR checks include Go, JavaScript/TypeScript and Python analyses                                                                                                             | Consult live findings/checks as well as tracked workflows.                                                                                                     |
| DCO app                                                                                                                                     | Reports commit-message sign-off validation                                                                                                                                         | Require valid contribution sign-offs and inspect the check details.                                                                                            |
| GitGuardian / Kusari                                                                                                                        | Recent PR checks include secret/security analysis                                                                                                                                  | Inspect reported findings; these checks are not named in the current classic required-status list. Secret scanning and push protection are enabled separately. |
| [Action CI](../.github/workflows/action-ci.yml)                                                                                             | Path-filtered PR checks for `action.yml` and the Action CI workflow                                                                                                                | Applicable only when those files trigger it; do not describe it as a check present on every PR.                                                                |
| [Release](../.github/workflows/release.yml), [SBOM](../.github/workflows/anchore-syft.yml), [Scorecard](../.github/workflows/scorecard.yml) | Post-merge pushes and/or scheduled jobs, according to each workflow                                                                                                                | These are distinct from required PR checks; contributors do not need a release deployment to merge.                                                            |

The audit found no configured coverage percentage gate. CI collects coverage, but the
guide must not invent a minimum percentage or claim that all Code Quality notes block
merge when the configured threshold is errors.

## Release and onboarding corrections

The old contribution guide described a protected `release` branch, cherry-pick release
flow and tag/manual dispatch triggers that the current workflow does not implement. The
development guide also described manual version edits and release creation.

The release workflow actually triggers on a push to `main`. It reads up to 50 commit
subjects since the previous tag: a `BREAKING` / `breaking change` subject marker selects
major, a `feat:` / `feat(scope):` subject selects minor, and other subjects select
patch. A body-only breaking-change footer or an exclamation mark alone does not match
that script. The revised guides describe this behavior and link the workflow.

The PR template now reminds contributors of DCO, signature, validation and documentation
requirements at submission time. Its checkboxes do not perform validation or change
merge enforcement.

## Evidence and maintenance

The audit read these GitHub API endpoints:

```text
GET /repos/OSSAfrica/skillguard/branches/main/protection
GET /repos/OSSAfrica/skillguard/rulesets/15202241
GET /repos/OSSAfrica/skillguard/rules/branches/main
```

It also checked repository merge/sign-off/security settings, branch inventory and PR
#201 checks, plus tracked workflows, [go.mod](../go.mod),
[.golangci.yml](../.golangci.yml) and integration tests.

For platform behavior, see GitHub's
[signature guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits),
[Copilot approval rule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#additional-approval-for-unattributed-copilot-pull-requests),
[code scanning gates](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-merge-protection),
[Code Quality thresholds](https://docs.github.com/en/code-security/how-tos/maintain-quality-code/set-pr-thresholds),
and the [DCO app documentation](https://github.com/dcoapp/app).

Recheck both protection layers, app checks and workflows when changing merge policy.
Update this audit date and the contributor guide together; do not infer active
requirements solely from a successful PR or the classic protection flags.
