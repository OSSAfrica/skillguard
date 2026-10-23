# SkillGuard Pre-commit Hook Example

This example shows how to integrate SkillGuard with [pre-commit](https://pre-commit.com/) to automatically scan AI skill definitions for security vulnerabilities before commits.

## Quick Start

1. Install pre-commit:

```bash
# Using pip
pip install pre-commit

# Using Homebrew (macOS)
brew install pre-commit
```

2. Add the `.pre-commit-config.yaml` file to your repository:

```yaml
repos:
  - repo: https://github.com/OSSAfrica/skillguard
    rev: v1.0.0  # Replace with the latest release tag
    hooks:
      - id: skillguard
        args: ["scan", "--path", ".", "--threshold", "70"]
```

3. Install the hooks:

```bash
pre-commit install
```

4. Test the hook:

```bash
pre-commit run --all-files
# Or, it will run automatically on git commit
```

## Advanced Configuration

### Scan Only Changed Files

To make the hook faster by scanning only changed Markdown files:

```yaml
repos:
  - repo: https://github.com/OSSAfrica/skillguard
    rev: v1.0.0
    hooks:
      - id: skillguard
        # pre-commit will pass changed .md files automatically
        args: ["scan", "--path"]
        files: \.md$
```

### Custom Threshold

Adjust the passing score threshold:

```yaml
repos:
  - repo: https://github.com/OSSAfrica/skillguard
    rev: v1.0.0
    hooks:
      - id: skillguard
        args: ["scan", "--path", ".", "--threshold", "80"]  # More strict
```

### Output Format

Generate markdown output for CI integration:

```yaml
repos:
  - repo: https://github.com/OSSAfrica/skillguard
    rev: v1.0.0
    hooks:
      - id: skillguard
        args: ["scan", "--path", ".", "--format", "markdown", "--output", "skillguard-report.md"]
```

## Testing Locally

You can test the pre-commit hook against this repository:

```bash
pre-commit try-repo https://github.com/OSSAfrica/skillguard
```

Or if you have cloned the repository locally:

```bash
pre-commit try-repo .
```

## How It Works

1. When you run `git commit`, pre-commit executes the SkillGuard hook
2. SkillGuard scans all `.md` files in your repository for AI skill definitions
3. If any skill scores below the threshold (default: 70), the commit is blocked
4. You can bypass with `git commit --no-verify` if needed (not recommended)

## Integration with CI

Combine pre-commit with GitHub Actions for comprehensive security:

1. **Local**: Pre-commit blocks vulnerable skills from being committed
2. **CI**: GitHub Action ensures no vulnerable skills exist in the repository

See the `examples/github-actions/` directory for CI integration examples.