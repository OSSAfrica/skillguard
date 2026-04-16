# SkillGuard

[//]: # ([![Go Version]&#40;https://img.shields.io/github/go-mod/go-version/ossafrica/skillguard&#41;]&#40;https://github.com/ossafrica/skillguard&#41;)

[//]: # ([![License]&#40;https://img.shields.io/github/license/skillguard/skillguard&#41;]&#40;LICENSE&#41;)

[//]: # ([![Build Status]&#40;https://img.shields.io/github/actions/workflow/status/skillguard/skillguard/scan.yml&#41;]&#40;.github/workflows/scan.yml&#41;)

[//]: # ([![Docker]&#40;https://img.shields.io/docker/pulls/skillguard/skillguard&#41;]&#40;https://hub.docker.com/r/skillguard/skillguard&#41;)

SkillGuard is a security scanner for AI agent "skills" defined in Markdown. It evaluates skill definitions for security risks, malicious intents, and supply chain vulnerabilities, providing transparency to developers and end-users.

## Why SkillGuard?

AI Agents are only as safe as the skills they are given. As the ecosystem of AI agents grows, so does the risk of:

- **Malicious skills** - Skills designed to exfiltrate data or perform harmful actions
- **Prompt injection** - Skills that can be manipulated to ignore safety guidelines
- **Supply chain attacks** - Compromised skill repositories
- **Excessive permissions** - Skills requesting unnecessary system access

SkillGuard provides the first line of defense by analyzing skill definitions before they're loaded into an agent.

## Features

- **YAML frontmatter parsing** - Extracts skill metadata from Markdown files
- **Security scoring** - 100-point scoring system with detailed findings
- **Risk detection**:
  - Shell command execution patterns
  - Credential and secret exposure
  - Unrestricted tool access (wildcards)
  - Prompt injection vectors
  - Untrusted external URLs
  - Missing metadata (transparency gaps)
- **CI/CD integration** - Threshold-based exit codes for automated pipelines
- **Multiple output formats** - Colored CLI output and JSON reports
- **Configurable** - Custom thresholds, paths, and trusted domains

## Installation

### Binary (Recommended)

Download the latest release for your platform from the [releases page](https://github.com/skillguard/skillguard/releases).

### Homebrew

```bash
brew install skillguard/skillguard/skillguard
```

### Docker

```bash
docker pull skillguard/skillguard:latest
```

### Build from source

```bash
git clone https://github.com/skillguard/skillguard.git
cd skillguard
go build -o skillguard .
```

## Quick Start

### Basic scan

```bash
skillguard scan
```

### Scan specific path

```bash
skillguard scan --path ./my-skills
```

### CI/CD integration (fail if score < 70)

```bash
skillguard scan --threshold 70
echo $?  # 0 = pass, 1 = fail, 2 = error
```

### Generate JSON report

```bash
skillguard scan --output report.json
```

## Command Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--path` | `-p` | Path to scan (file, directory, or comma-separated paths) | `~/.agents/skills` |
| `--threshold` | `-t` | Minimum score to pass (0-100) | `70` |
| `--output` | `-o` | Output JSON report to file | (stdout) |
| `--quiet` | `-q` | Minimal output - just pass/fail status | `false` |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, all skills passed threshold |
| `1` | Scan completed, one or more skills failed threshold |
| `2` | Scan failed (file not found, parse error, etc.) |

## Configuration

SkillGuard reads configuration from `~/.skillguard.yaml`. Create or modify this file to set defaults:

```yaml
default_path: ~/.agents/skills
threshold: 70
```

Or use the config command:

```bash
skillguard config set --path ~/my-skills --threshold 80
skillguard config show
```

## Security Scoring

Skills start with a score of 100 and receive deductions for identified risks:

| Category | Risk | Deduction |
|----------|------|-----------|
| Tool Access | Unrestricted wildcard access | -15 per finding |
| Shell Execution | Command execution patterns | -20 per finding |
| File Access | File write/delete operations | -15 per finding |
| Network | Untrusted external URLs | -10 per finding |
| Credentials | Secret/credential references | -20 per finding |
| Prompt Injection | Dynamic prompt construction | -15 per finding |
| Supply Chain | No source URL provided | -10 |
| Metadata | Missing description/triggers | -5 each |

A score of 70 or higher is considered passing by default.

## Trusted Domains

SkillGuard includes built-in trust for known safe domains:

- Code hosts: `github.com`, `gitlab.com`, `bitbucket.org`
- Package managers: `npmjs.com`, `pypi.org`, `crates.io`
- Cloud platforms: `vercel.app`, `vercel.sh`, `cloudflare.com`, `google.com`
- Documentation: `github.io`, `readthedocs.io`, `netlify.app`

External URLs to domains not in this list are flagged as medium-risk.

## Docker Usage

### Scan local skills

```bash
docker run --rm -v ~/path/to/skills:/skills skillguard/skillguard scan --path /skills
```

### CI/CD Integration

Copy the appropriate example to your skill repository:

| Platform | Example Location |
|----------|------------------|
| GitHub Actions | `examples/github-actions/skill-scan.yml` |
| GitLab CI | `examples/gitlab-ci/.gitlab-ci.yml` |
| Docker Compose | `examples/docker/docker-compose.yml` |

## Project Structure

```
skillguard/
├── cmd/              # CLI commands (Cobra)
│   ├── root.go        # Main entry point
│   ├── scan.go       # Scan command
│   └── config.go     # Config management
├── internal/
│   ├── model/         # Data structures
│   ├── parser/        # Markdown/YAML parsing
│   └── analyzer/      # Security scoring engine
├── examples/          # CI/CD integration examples
│   ├── github-actions/
│   ├── gitlab-ci/
│   └── docker/
├── Dockerfile         # Container image definition
└── main.go           # Application entry
```

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for instructions on setting up a development environment.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Inspired by tools like Snyk, Socket.dev, and npm audit for bringing security transparency to software ecosystems.