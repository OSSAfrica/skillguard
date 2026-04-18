---
name: Bug report
about: Create a report to help us improve SkillGuard
title: '[BUG]'
labels: bug
issue_type: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is. Is it a false positive in a scan, a parsing error, or a CLI crash?

**Skill Definition (if applicable)**
If the bug is related to a specific skill being scanned, please provide the Markdown/YAML content here (ensure sensitive
data is redacted):

```markdown
---
# Insert the skill definition here
---
```

**To Reproduce**
Steps to reproduce the behavior:

1. Run command `skillguard scan --path ...`
2. Provide flag `....`
3. See error/unexpected output

**Expected behavior**
What did you expect to happen? (e.g., "The score should be 70, but it returned 40" or "This pattern should be flagged as
High Risk").

**Environment Information:**

- **SkillGuard Version:** [e.g. v0.5.3 or commit hash]
- **Go Version:** [e.g. 1.22]
- **OS:** [e.g. Ubuntu 22.04, macOS, Windows]
- **Installation Method:** [e.g. Homebrew, Docker, Source]

**Scan Output/Logs**
If applicable, paste the terminal output or the JSON report results:

```json
// Insert JSON output if using --output json
```

**Additional context**
Add any other context about the problem here (e.g., specific regex patterns in `internal/analyzer` that might be
failing).
