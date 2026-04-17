# SkillGuard

[![Go Version](https://img.shields.io/github/go-mod/go-version/OSSAfrica/skillguard)](https://github.com/OSSAfrica/skillguard)
[![License](https://img.shields.io/github/license/OSSAfrica/skillguard)](LICENSE)
[![Docker Image Size](https://img.shields.io/docker/image-size/OSSAfrica/skillguard/latest)](https://hub.docker.com/r/OSSAfrica/skillguard)
[![Version](https://img.shields.io/github/v/release/OSSAfrica/skillguard)](https://github.com/OSSAfrica/skillguard/releases)
[![Minimalism](https://img.shields.io/badge/minimalism-A-gold?style=flat-square&labelColor=3443F4&color=04B45F)](https://github.com/OSSAfrica/skillguard/actions)
[![Provenance](https://img.shields.io/badge/provenance-A-gold?style=flat-square&labelColor=3443F4&color=04B45F)](https://github.com/OSSAfrica/skillguard/actions)
[![Configuration](https://img.shields.io/badge/configuration-A-gold?style=flat-square&labelColor=3443F4&color=04B45F)](https://github.com/OSSAfrica/skillguard/actions)
[![CVEs](https://img.shields.io/badge/cves-A%2B-gold?style=flat-square&labelColor=3443F4&color=04B45F)](https://github.com/OSSAfrica/skillguard/actions)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/OSSAfrica/skillguard?label=OpenSSF)](https://securityscorecards.dev/details/github.com/OSSAfrica/skillguard)

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
- **Multi-category security scoring** - Weighted scoring with exponential decay
- **Risk detection**:
  - Shell command execution patterns
  - Credential and secret exposure
  - Unrestricted tool access (wildcards)
  - Prompt injection vectors
  - Untrusted external URLs
  - Obfuscated code (eval, Function, setTimeout)
  - HTTP/Git dependencies
  - Hidden characters (zero-width, RTL override, homoglyphs)
  - Referenced script analysis (scans .py, .js, .ts, .sh files)
  - Missing metadata (transparency gaps)
- **CI/CD integration** - Threshold-based exit codes for automated pipelines
- **Multiple output formats** - Colored CLI output and JSON reports
- **Configurable** - Custom thresholds, paths, and trusted domains

## Installation

### Binary (Recommended)

Download the latest release for your platform from the [releases page](https://github.com/OSSAfrica/skillguard/releases).

### Homebrew

```bash
brew install skillguard/skillguard/skillguard
```

### Docker

```bash
# GitHub Container Registry (Chainguard-based, distroless)
docker pull ghcr.io/ossafrica/skillguard:latest

# Or from Docker Hub
docker pull OSSAfrica/skillguard:latest
```

### Build from source

```bash
git clone https://github.com/OSSAfrica/skillguard.git
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

SkillGuard uses a multi-category scoring system with weighted averages. Skills start with 100 points in each category, with deductions based on severity and exponential decay for repeated findings.

### Score Categories

| Category | Weight | Description |
|----------|--------|-------------|
| Security | 3.0 | Shell access, file access, credentials, obfuscated code |
| Supply Chain | 2.0 | External scripts, git/http dependencies, source verification |
| Transparency | 1.5 | Metadata completeness, prompt injection risks |
| Quality | 1.5 | Tool access patterns, allowed tools |
| Maintenance | 1.0 | Telemetry, protestware detection |

### Severity Levels

| Level | Base Deduction | Decay Factor |
|-------|----------------|--------------|
| Critical | 40 | e^-10x |
| High | 20 | e^-x |
| Medium | 10 | e^-x/20 |
| Low | 5 | e^-x/40 |

### Detection Categories

| Category | Risk | Severity |
|----------|------|----------|
| Shell Execution | Command execution patterns | High/Critical |
| File Access | File write/delete operations | High |
| Network | Untrusted external URLs | Medium |
| Credentials | Secret/credential references | High |
| Obfuscated Code | eval, Function, setTimeout patterns | Critical |
| HTTP Dependencies | curl/wget with pipe to shell | Critical |
| Git Dependencies | Git clone/fetch operations | Medium |
| Hidden Characters | Zero-width, RTL, homoglyphs | High |
| Prompt Injection | Dynamic prompt construction | Medium |
| Supply Chain | No source URL provided | Low |
| Metadata | Missing description/triggers | Low |

A score of 70 or higher is considered passing by default.

### Example Output

```
Score: 77/100
Category Scores:
  security: 62/100 (3 findings)
  supply_chain: 55/100 (2 findings)
  quality: 100/100
  maintenance: 100/100
  transparency: 95/100 (1 findings)
```

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
docker run --rm -v ~/path/to/skills:/skills ghcr.io/ossafrica/skillguard scan --path /skills
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