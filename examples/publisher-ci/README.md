# Publisher checks

Copy the workflow example into the documentation publisher's repository only
after reviewing it. No workflow or schedule is installed by these examples.
It scans `llms.txt` and `llms-full.txt` on documentation pull requests, manual
requests, and an optional weekly schedule. Remove absent file names explicitly;
a missing requested file correctly causes an incomplete result.

Check in an operator-reviewed `.security/llms-verification.json` on the protected
default branch using the sample policy as a starting point. Replace the sample
package disclosure lists with intended public names; do not disclose internal
names to public registries. Point private packages only at the correct private
metadata endpoint with explicit disclosure permission. The example needs no
registry secrets and deliberately does not expose secrets to fork pull requests.
Do not switch it to `pull_request_target` to run untrusted checkout instructions.

The scanner is built from a reviewed immutable SkillGuard commit, independently
of the target documentation, using its pinned module checksums. Update that pin
through ordinary review. The policy checkout comes from the publisher's protected
default branch so proposed documentation cannot silently relax its own policy.
Protect workflow changes as well as policy changes. The job never invokes an
install command from the documents or executes publisher-provided build scripts.

Exit 1 means score/reference findings, including missing package/version records.
Exit 2 means required coverage or lookup failure, including blocked disclosure,
unsupported syntax, timeouts and unreadable inputs. Both fail the job. Neither
means that a domain is available to register or that exploitation occurred.
A name claimed by an attacker may already exist at lookup time: metadata alone
will not catch that identity substitution. Fix documentation, independently review
package identity/artifacts, and retain agent-side action gates.

Local failure fixtures live in `internal/verify` and `internal/assess`: missing
registry records and lookup failures produce distinct states. They use synthetic
metadata, not package downloads or malicious installations. The workflow's summary
counts states without treating untrusted metadata strings as shell instructions.
