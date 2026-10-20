# Documentation inputs and static command extraction

SkillGuard can scan AI-readable documentation before an agent acts on its setup
instructions. It inventories a supported subset of installation, package-execution,
and download commands alongside the existing static security findings.

**This feature does not authorize execution.** A passing security score or a
`complete` extraction is not proof that a package, domain, or command is safe.
Opt-in [reference metadata verification](reference-verification.md) adds registry
observations without establishing identity. Action decisions and harness
enforcement remain separate work in [#184](https://github.com/OSSAfrica/skillguard/issues/184)
and [#185](https://github.com/OSSAfrica/skillguard/issues/185).

## Inputs

```sh
# Directory discovery includes Markdown and these two conventional text names.
skillguard scan ./docs

# Any explicitly named UTF-8 text file can be scanned without skill frontmatter.
skillguard scan ./docs/llms.txt ./vendor/setup.txt --format json

# Read one stdin stream; --source is an optional display identity.
skillguard scan - --source https://docs.example.org/llms-full.txt --format json < downloaded.txt
```

Directory scans include `.md`, `llms.txt`, and `llms-full.txt` (case-insensitive).
They do not sweep every `.txt` file. Explicit non-Markdown inputs are treated as
documentation; apparent YAML delimiters are kept as untrusted text. Existing
Markdown skill/reference classification remains in effect. Documentation does not
receive missing-skill-metadata deductions.

Each top-level input must be a regular UTF-8 text file (or stdin), contain no NUL
bytes, and fit within 1 MiB. Unsupported, unreadable, oversized, or unparseable
discovered inputs are reported in the report's `coverage_gaps` rather than silently omitted
from machine output. Skipped discovery/analysis or no analyzed inputs produce exit
2 after rendering the available report. This deliberately closes the previous
silent-success behavior for incomplete input scans. Stdin can be supplied once, optionally alongside file paths.
Its source label is never fetched, used as a directory, or passed to a shell.
Fatal request/path-resolution errors can occur before a report exists; they use
stderr and exit 2. A uniform action-assessment error contract belongs to #184.

## Supported command subset

| Command | Observations |
| --- | --- |
| `npm install`, `npm i`, `npm add` | Registry packages, scoped names, aliases, version/tag/range specifications, direct URL/Git/local sources |
| `npm install` without explicit packages; `npm ci` | References to `package.json` and `package-lock.json`; resolution remains incomplete |
| `npx`, `npm exec` | First package target or explicit `--package` / `-p` specifications; program arguments are not treated as more dependencies |
| `pip install`, `pip3 install`, `python -m pip install`, `python3 -m pip install` | Distribution names normalized per Python conventions, quoted extras/version constraints, direct references, `-r`/`--requirement` and `-c`/`--constraint` inputs |
| `uvx` | First package target or an explicit `--from` specification |
| `pipx run` | First package target or an explicit `--spec` specification |
| `curl`, `wget` | Literal HTTP(S) download destinations; direct pipelines into common shell/Python interpreters are identified |

Only an explicit subset of options is interpreted. For example, npm `--registry`
and Python `--index-url`, `--extra-index-url`, and `--find-links` are recorded as
destinations. Unknown flags, ambiguous option values, wrappers, environment
overrides, control flow, altered execution context, and unsupported commands leave
coverage gaps. Global package-manager options preceding subcommands are not
reordered or inferred. Shell interpreters such as `bash -c` are not recursively
interpreted. Transport/download options do not establish artifact identity.

Candidate discovery covers shell/console fences (including empty language
labels), recognizable inline code, command-starting lines, and simple imperative
prefixes such as `Run`. It supports continuations and compound shell statements.
It uses a syntax-only Bash parser after candidate discovery, never a shell
interpreter. Inline explanatory examples are labeled `example` when recognizable;
that label is a heuristic, not a security exemption.

This is not a general Markdown interpreter, a PowerShell/fish parser, or a scanner
for arbitrary embedded programming-language strings. Descriptive prose outside
the recognized candidate forms is not interpreted as executable shell. A
recognized command in a non-shell fence produces an unsupported-language gap.
Unquoted shell globbing, variable expansion, and substitutions are unresolved.
Quote package extras and version constraints when needed by the shell.

## Structured observations

Each result adds `extraction`:

```json
{
  "status": "complete",
  "commands": [{
    "tool": "npm",
    "operation": "install",
    "context": "fenced",
    "location": {"source": "llms.txt", "start_line": 4, "end_line": 4},
    "evidence": "npm install (untrusted candidate sha256:...)",
    "dependencies": [{"ecosystem": "npm", "name": "@vendor/helper", "specifier": "1.2.3", "source": "registry"}],
    "destinations": [{"url": "https://registry.example.org/", "role": "registry"}]
  }],
  "gaps": []
}
```

Locations use one-based, inclusive lines in the original input, including
frontmatter and Markdown delimiters. `context` describes where the suggestion
was found (`plain`, `instruction`, `inline`, `example`, or `fenced`). Dependency
`source` distinguishes registry, URL, Git, local, and unresolved specifications.
It does not attest to authenticity. No default registry or effective configuration
is inferred in this phase. The package supplying an executable may still need
resolution using actual project context.

`complete` means the recognized candidates fit this documented extraction subset;
it does not mean all executable behavior in the document has been discovered.
`partial` means at least one coverage gap occurred. No supported commands produces
`no_assessable_commands`, not a safety conclusion. Coverage is independent of the
existing score and `passed` fields, which retain their scoring meaning. Per-result
extraction gaps do not change score-based exit codes: scanning text completely can
still leave its proposed behavior unresolved. The CLI's score exit codes are not
an action authorization contract: consumers must not use exit 0 alone to approve
an installation.

Common gap codes include `invalid_shell`, `dynamic_shell`, `unsupported_command`,
`unsupported_option`, `unsupported_language`, `environment_unresolved`,
`control_flow`, `dependency_resolution_required`, `dependency_input_unresolved`,
`input_unavailable`, `input_outside_boundary`, `input_base_unavailable`,
`input_limit`, `extraction_limit`, and `no_assessable_commands`. Top-level skipped
inputs appear under report-level `coverage_gaps` with `input_not_analyzed`,
`discovery_incomplete`, or `no_assessable_input`.

JSON includes the full inventory and gaps. Text output summarizes extraction and
shows details with `--verbose`; Markdown reports include the inventory and gaps.
Warnings use stderr so JSON stdout remains parseable.

## Local dependency inputs and resource boundaries

Local input references are inventory entries with a kind and a readability status.
For a file scan, readability is checked inside the document's own directory using
Go's filesystem root confinement, including symlink protection. Absolute paths,
URLs, and unsupported path forms do not grant file access. Stdin has no local
directory boundary, regardless of its source label.

At most 16 dependency inputs are read per document, each at most 1 MiB. Their
contents are discarded rather than copied into reports. `readable` does not mean
resolved or verified. Manifest dependencies, lockfile integrity, recursive
requirements, local package contents, private-index configuration, and transitive
dependencies remain unresolved and are reported as coverage gaps. Missing optional
lockfiles are also visible rather than assumed to be authoritative inputs.

Extraction is bounded to 256 commands, 512 arguments per command, and 256 coverage
gaps per document. Hitting a limit is explicit. Credentials, URL queries, and
fragments are removed from destination evidence. Raw command arguments and parser
error snippets are not included; evidence is reconstructed from recognized tools
and operations with a candidate hash. New evidence remains untrusted data, and
untrusted excerpts must never become agent instructions. URL paths and package
identities can still be sensitive; control access to reports accordingly.

SkillGuard never installs the extracted packages, executes scanned commands, or
downloads referenced content. A domain resolving, a registry hosting a package,
or a version being pinned would not by itself establish legitimacy even once
registry verification is implemented.
