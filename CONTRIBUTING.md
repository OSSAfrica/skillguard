# Contributing to SkillGuard

Contributions go through pull requests targeting `main`. Before submitting, sign off and
cryptographically sign your commits, run the checks relevant to your change, and explain
the resulting behavior and validation.

[Commit requirements](#commit-requirements) · [Local checks](#local-validation) ·
[Merge requirements](#review-and-merge-requirements) ·
[Troubleshooting](#when-a-pull-request-is-blocked)

## Discuss the change

- Search existing issues before reporting a bug. Include reproduction steps, expected
  behavior, actual behavior and the SkillGuard version.
- Open an issue before a substantial feature or architecture change. Describe the
  problem and proposed behavior so maintainers can discuss scope.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Report vulnerabilities through the [security policy](SECURITY.md), rather than a
  public issue containing exploit details or credentials.

## Set up a branch

Fork the repository, then replace `YOUR_USERNAME` and the example branch name:

```sh
git clone https://github.com/YOUR_USERNAME/skillguard.git
cd skillguard
git remote add upstream https://github.com/OSSAfrica/skillguard.git
git fetch upstream
git switch -c fix/describe-your-change upstream/main
```

Use Go 1.25 or newer, as specified in [go.mod](go.mod). Python 3.10+ and a current
supported Node.js release with `node --test` are needed for the integration contracts.
CI runs on Ubuntu; some process-control and loopback-network fixtures require Unix and
permission to bind local ports. Installed Claude, Codex and OpenCode clients are needed
only for the separate opt-in live-client tests.

See [Development](DEVELOPMENT.md) for local setup and [Architecture](ARCHITECTURE.md)
for components and trust boundaries.

## Commit requirements

### DCO sign-off and signature are separate requirements

| Requirement                              | Git option                    | What it does                                                       | How to check                                                            |
| ---------------------------------------- | ----------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| Developer Certificate of Origin sign-off | Lowercase `-s` / `--signoff`  | Adds a `Signed-off-by: Name <email>` trailer to the commit message | Inspect the message and the PR's `DCO` check                            |
| Cryptographic commit signature           | Uppercase `-S` / `--gpg-sign` | Signs the commit using your configured signing key                 | Check the signature locally and the commit's GitHub **Verified** status |

Use both when creating a contribution commit:

```sh
git add path/to/changed-file
git commit -S -s -m "fix(parser): describe the behavior being corrected"
```

Apply these requirements to each contribution commit, including follow-up fixes. A
signed-off commit does not add a cryptographic signature, and signing a commit does not
add a DCO trailer. Signing only the final commit leaves earlier commits unchanged.

### DCO compliance

Read the [Developer Certificate of Origin](https://developercertificate.org/). Signing
off certifies your right to submit the contribution under its applicable open source
license. The sign-off becomes part of the public commit history.

Configure your own name and author email for this checkout:

```sh
git config --local user.name "Your Name"
git config --local user.email "you@example.com"
```

For your own commits, the trailer must match the commit author's identity. Use your
GitHub-associated email; a correctly configured GitHub noreply address can preserve
email privacy. Preserve other contributors' authorship and sign-offs. Do not invent a
sign-off for someone else.

The [DCO app](https://github.com/dcoapp/app) reports compliance on PRs. No repository
configuration currently enables individual or third-party remediation commits. Adding an
unrelated signed-off commit or a trailer to the PR description does not repair missing
trailers in earlier commits.

### GPG signing setup

The active `main` ruleset requires verified signatures. The example below uses GPG;
GitHub also supports verified SSH and S/MIME signatures. Use a signing method that
produces GitHub **Verified** commits. See
[GitHub's signing guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

For GPG, create or select a signing key, add its **public** key to your GitHub account,
and use a committer email associated with that key and verified on GitHub. Follow
[GitHub's key configuration instructions](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key).
Then configure this checkout, replacing `YOUR_GPG_KEY_ID`:

```sh
git config --local gpg.format openpgp
git config --local user.signingkey YOUR_GPG_KEY_ID
git config --local commit.gpgsign true
```

These commands select the GPG workflow. If you already use verified SSH or S/MIME
signing, retain the matching configuration. Signing by default does not add DCO
sign-off; continue using `git commit -S -s`.

Before pushing, inspect your contribution commits:

```sh
git log --show-signature upstream/main..HEAD
git log --format='%h %an <%ae>%n%B' upstream/main..HEAD
```

After pushing, inspect the PR's **Commits** tab for verified signatures and the `DCO`
check for trailers. A locally valid signature alone does not establish that GitHub
recognizes the key and email.

### Commit messages

Use a Conventional Commit subject:

```text
<type>(optional-scope): describe the change
```

Common types are `feat`, `fix`, `docs`, `refactor`, `test`, `chore` and `ci`. Explain
non-obvious tradeoffs in the body. Keep unrelated changes in separate commits or PRs.
See [release behavior](#releases-and-versioning) before naming a breaking change.

## Local validation

Run checks relevant to your changes before pushing; GitHub runs the full applicable CI
suite. Documentation-only changes need working links, valid code fences and accurate
examples. Behavior changes need focused tests, including a regression for a corrected
bug. Security changes should cover both permitted behavior and denial/error paths.

### Go checks

```sh
go fmt ./...
go vet ./...
go test -v -race -cover ./...
go build -o skillguard .
./skillguard --version
./skillguard scan --help
git diff --check
```

The [`test` CI job](.github/workflows/ci.yml) also runs golangci-lint using
[.golangci.yml](.golangci.yml) and a separate gosec scan. With reviewed installations of
those tools, reproduce their checks using:

```sh
golangci-lint run --timeout=5m
gosec -exclude-generated -exclude-dir=examples ./...
```

The linter configuration uses golangci-lint v2. CI currently selects the latest
available linter; inspect the job log for the version used on your PR. A successful
`go test` alone does not cover the full `test` job.

### Harness and plugin contracts

These are the Python/Node contracts included in CI. Build a temporary scanner so
integration cases do not silently skip for lack of `SKILLGUARD_TEST_SCANNER`:

```sh
skillguard_check_dir="$(mktemp -d)"
go build -o "$skillguard_check_dir/skillguard" .

SKILLGUARD_TEST_SCANNER="$skillguard_check_dir/skillguard" \
  python3 -I -m unittest discover -s examples/harness -p 'test_*.py' -v
SKILLGUARD_TEST_SCANNER="$skillguard_check_dir/skillguard" \
  python3 -I -m unittest discover -s integrations/clients -p 'test_*.py' -v
python3 -I -m unittest discover -s integrations/plugins -p 'test_*.py' -v

node --test integrations/clients/opencode-plugin/test.mjs
node --test integrations/plugins/test_opencode.mjs
```

The tests use synthetic inputs and fake executors; they do not install packages from
untrusted documentation. Remove your temporary scanner directory when finished.

Changes to client restrictions, native packaging or runtime pins also need the relevant
opt-in live-client validation. Follow the version and setup requirements in
[protected launcher validation](docs/client-integration-validation.md) and
[native plugin validation](docs/native-plugin-validation.md). These runs are separate
from standard CI and do not certify arbitrary host/plugin combinations.

### Coding and documentation standards

- Follow Go conventions and document exported interfaces. Keep dependency additions
  justified and commit the corresponding `go.mod` / `go.sum` changes.
- Preserve bounded parsing, explicit coverage gaps, protected operator configuration and
  the separation between scan evidence, assessment and execution. See
  [policy contracts](docs/policies.md) and
  [harness integration](docs/harness-integration.md).
- Update affected CLI examples, schemas and user docs when behavior changes.
- Keep credentials, private keys, personal reports, runtime caches and build outputs out
  of commits. Secret scanning and push protection are enabled on this repository.
- Address security findings with a fix or a maintainer-reviewed explanation; do not
  weaken a check merely to turn CI green.

## Submit the pull request

Push your branch to your fork and open a PR against `OSSAfrica/skillguard:main`:

```sh
git push -u origin HEAD
```

Use the PR template to explain the problem, resulting behavior, validation performed and
any limits. Link the issue when one exists. Mark unfinished work as a draft, then
request review when the change is ready.

If `main` advances, update your branch and rerun applicable checks. A signed merge
preserves existing commit history:

```sh
git fetch upstream
git merge -S --signoff upstream/main
git push origin HEAD
```

Resolve conflicts and review the result before pushing. GitHub requires the branch to be
up to date; it does not require rebasing as the only update method. If you choose to
rebase, recreated commits need valid sign-offs and fresh signatures too.

## Review and merge requirements

The combined rules below were checked on **20 October 2026**. The
[live ruleset](https://github.com/OSSAfrica/skillguard/rules/15202241) and PR merge box
show the current requirements; see the [audit record](docs/contribution-requirements.md)
for the distinction between enforced gates and contribution policy.

| Requirement               | Before merge                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pull request and approval | Target `main` and obtain at least one qualifying reviewer approval. The author cannot approve their own PR. New commits can dismiss previous approvals.                                                                                                                                                                                                           |
| Unattributed Copilot PR   | The enabled ruleset adds one approval when Copilot opens a PR not attributed to a person, bringing its requirement to two. See GitHub's [rule explanation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#additional-approval-for-unattributed-copilot-pull-requests). |
| Verified signatures       | Contribution commits must satisfy the active ruleset's signature verification requirement.                                                                                                                                                                                                                                                                        |
| DCO                       | Contribution commits need valid sign-off trailers and a passing `DCO` check. This is contribution policy; `DCO` is not currently a named required status context in branch protection.                                                                                                                                                                            |
| Required CI               | `test` and `build` must pass on the current revision. The branch must be up to date with `main`.                                                                                                                                                                                                                                                                  |
| Code scanning             | Required CodeQL results must be available and meet the configured thresholds: security alerts at high or critical severity, and error/warning alerts, block merge.                                                                                                                                                                                                |
| Code quality              | The required Code Quality analysis must have no unresolved findings at the configured error threshold. A completed workflow is not itself proof that alert gates passed.                                                                                                                                                                                          |
| Other reported checks     | Review applicable GitGuardian, Kusari and path-specific Action CI results. Resolve failures or obtain a maintainer's documented disposition; these are not all named required status contexts.                                                                                                                                                                    |
| Review feedback           | Address requested changes and explain unresolved questions to the reviewer. Automatic tool comments or an AI-generated review do not replace a qualifying reviewer approval.                                                                                                                                                                                      |

`main` disallows force pushes and deletion. Merge, squash and rebase methods are
currently enabled; maintainers select a method that satisfies signatures, DCO and the
final checks. The normal contribution path uses the checks and approval above rather
than an administrative bypass.

### Pre-merge checklist

- [ ] The change is focused, explains the problem and links its issue when applicable.
- [ ] Contribution commits have matching DCO trailers and GitHub-verified signatures.
- [ ] Relevant local checks pass; behavior changes include appropriate tests.
- [ ] Affected documentation, examples and schemas are current.
- [ ] The branch is current, conflicts are resolved and required CI passes.
- [ ] CodeQL/Code Quality gates and applicable security checks are addressed.
- [ ] A qualifying reviewer has approved the current change and requested changes are
      addressed.

## When a pull request is blocked

**DCO failure:** inspect the failing commit IDs in the check details. A PR-description
trailer or a later signed-off commit does not repair those commits. For your own latest
commit that you have not pushed, add the trailer and signature with:

```sh
git commit --amend --no-edit -S -s
```

For already-pushed commits, coordinate with maintainers before rewriting a shared
branch. One option that keeps the existing branch intact is to create a replacement
branch and copy your own ordinary commits, oldest first, using
[`git cherry-pick -S -s`](https://git-scm.com/docs/git-cherry-pick):

```sh
git fetch upstream
git switch -c fix/signed-contribution upstream/main
git cherry-pick -S -s YOUR_COMMIT_SHA
git push -u origin HEAD
```

Replace `YOUR_COMMIT_SHA` with a commit you authored and repeat for the relevant
commits. Retest and open a replacement PR linked to the original. For mixed authors or
merge commits, ask a maintainer to help preserve attribution and sign-offs.

**Unsigned or unverified commit:** confirm your signing format, key and committer email.
For GPG, GitHub needs your public key and a matching verified email. Recreate unsigned
commits with signatures; check the status of all contribution commits after any history
change.

**Checks waiting for permission:** fork PR workflows may require a maintainer to approve
the run. That approval allows CI to run; it is separate from approval to merge. Ask a
maintainer to inspect the pending run rather than removing checks or exposing secrets to
fork workflows.

**Missing analysis or failed CI:** open the failing job/check details. Missing results
are not a pass. Share the failing step and relevant sanitized logs when asking for help.
GitHub CLI users can replace `PR_NUMBER` and monitor checks with:

```sh
gh pr checks PR_NUMBER --repo OSSAfrica/skillguard --watch
```

## Releases and versioning

The [release workflow](.github/workflows/release.yml) runs on pushes to `main`,
including merged PRs. It calculates a version, creates a tag and publishes release
artifacts; contributors do not maintain a separate `release` branch or manually create
tags as part of an ordinary PR.

The current version calculation reads commit **subjects** since the previous tag,
limited to the latest 50. A subject containing `BREAKING` or `breaking change` selects a
major bump; otherwise `feat:` / `feat(scope):` selects minor; otherwise it selects
patch, including documentation and maintenance changes. A breaking-change footer or `!`
marker alone does not trigger the current script. Put `BREAKING` in the subject and
explain migration steps in the PR for a breaking change.

Release jobs publish binaries and containers, sign the container digest and attach SBOM
information. These are post-merge jobs, separate from PR merge checks.
