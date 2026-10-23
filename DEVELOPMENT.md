# Development Guide

This guide covers how to set up a development environment for SkillGuard. Before
submitting a PR, follow [Contributing](CONTRIBUTING.md) for DCO sign-off, verified
commit signatures and the complete validation checklist.

## Prerequisites

- Go 1.25 or higher
- Git
- A text editor or IDE (VS Code, GoLand, etc.)

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/OSSAfrica/skillguard.git
cd skillguard
```

### 2. Install Dependencies

```bash
go mod download
```

### 3. Build the Project

```bash
go build -o skillguard .
```

### 4. Run Tests

```bash
go test -v ./...
```

## Project Structure

```
skillguard/
├── cmd/                   # CLI commands
│   ├── root.go           # Main command
│   ├── scan.go           # Scan subcommand
│   └── config.go         # Config subcommand
├── internal/
│   ├── model/            # Data types
│   │   └── types.go
│   ├── parser/           # Skill file parsing
│   │   └── markdown.go
│   └── analyzer/        # Security analysis
│       └── scorer.go
├── .github/workflows/    # CI/CD
├── Dockerfile
├── main.go
└── go.mod
```

## Development Workflow

### Running the CLI Locally

```bash
# Build and run
go build -o skillguard . && ./skillguard --help

# Or use go run
go run . scan --help
```

### Adding a New Security Check

1. **Define the finding type** in `internal/model/types.go`:

   ```go
   const (
       CategoryNewCheck Category = "new_check"
   )
   ```

2. **Add the detection logic** in `internal/analyzer/scorer.go`:

   ```go
   func (s *Scorer) checkNewRisk(body string) []model.Finding {
       var findings []model.Finding
       // detection logic here
       return findings
   }
   ```

3. **Call the check** in `Analyze()` method:

   ```go
   result.Findings = append(result.Findings, s.checkNewRisk(body)...)
   ```

4. **Add tests** in `internal/analyzer/scorer_test.go`

### Running Specific Tests

```bash
# Run all tests
go test ./...

# Run tests in specific package
go test ./internal/analyzer/ -v

# Run specific test
go test -run TestScorer_Analyze -v
```

### Code Formatting

```bash
# Format code
go fmt ./...

# Lint
go vet ./...
```

## Testing New Skills

Create test skill files in a temporary directory:

```bash
mkdir /tmp/test-skills
```

Example skill file (`/tmp/test-skills/test.md`):

```markdown
---
name: test-skill
description: A test skill
triggers: ["test", "example"]
---

# Test Skill

This skill runs commands.
```

Scan the test skills:

```bash
./skillguard scan --path /tmp/test-skills
```

## Debugging

### Enable verbose output

Currently, debug output can be enabled by modifying the source code to add print
statements or using a debugger.

### Common Issues

**YAML parsing errors**

- Ensure frontmatter uses `---` delimiters
- Check YAML syntax with `yamllint`

**Regex issues**

- Test patterns at https://regex101.com
- Use `regexp.MustCompile` with care - invalid patterns cause panics

## Release process

The [release workflow](.github/workflows/release.yml) runs on pushes to `main`. It
calculates the next version from commit subjects, creates a tag and publishes artifacts.
Ordinary contributions do not require manual tags, changes to a version constant or a
separate release branch. See [Contributing](CONTRIBUTING.md#releases-and-versioning) for
the current version rules and contributor workflow.

## Dependencies

Key dependencies (see `go.mod`):

- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration
- `github.com/fatih/color` - Colored output
- `gopkg.in/yaml.v3` - YAML parsing

Keep dependencies minimal to reduce attack surface and improve performance.
