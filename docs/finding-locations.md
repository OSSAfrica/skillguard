# Finding source locations

[Documentation](README.md) / Finding source locations

Scan findings include their input identity in `location`. Findings tied to visible
content also include `line` and `column`, both one-based. Text output (when findings
are shown), Markdown stdout, and saved Markdown reports display `file:line:column`.
JSON reports and MCP scan responses expose the same fields:

```json
{
  "category": "prompt_injection",
  "severity": "critical",
  "description": "Injected instructions directed at the agent (instruction override, secrecy or coercion)",
  "location": "skills/helper/SKILL.md",
  "line": 12,
  "column": 5
}
```

Positions refer to the original input snapshot, including frontmatter, blank lines,
indentation and a leading byte-order mark. Columns count Unicode code points, not
UTF-8 bytes, UTF-16 code units or display cells; a tab counts as one column. CRLF
line endings do not shift the following line's position. Editors using a different
column convention may place the cursor differently after emoji or tabs.

Body detectors point to the first match of the pattern that produced the finding.
For injected instructions, leading sentence-boundary punctuation, whitespace and
Markdown decoration are skipped. A hidden HTML-comment finding points to `<!--`.
Hidden-character and mixed-script findings point to the first relevant character.
The existing detector priority and aggregation are preserved: this is not a report
of every occurrence, and adding positions does not add scoring deductions.

Tool-access findings point to the YAML value node declaring the tool. A quoted,
escaped, folded or comma-separated value is anchored at the start of that scalar;
sequence entries have their own anchors. Missing metadata such as an absent
`source`, `description` or `triggers` is a file-level finding: `line` and `column`
are omitted rather than assigned a fabricated position.

Referenced-script findings identify the script file and its own coordinates, not
the parent skill's line numbers. Existing path boundaries and read limits apply.
For stdin/MCP content, positions refer to the submitted text and `location` is the
sanitized display label. That label is never fetched or treated as filesystem access.

The existing string `location` field is retained. Optional integer `line` and
`column` fields are additive; consumers should handle findings without positions.
The score breakdown copies the same coordinates as the main findings list.
Command-extraction spans and action-assessment response schemas are unchanged.
A source position is evidence for review, not execution permission.
