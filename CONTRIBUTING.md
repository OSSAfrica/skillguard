# Contributing to SkillGuard

Thank you for your interest in contributing to SkillGuard. This document outlines the process for contributing and the standards we follow.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. We expect all contributors to be respectful, inclusive, and professional.

## How to Contribute

### Reporting Issues

1. Search existing issues to avoid duplicates
2. Use the issue template when creating a new issue
3. Include reproduction steps, expected behavior, and actual behavior
4. For security vulnerabilities, please see Security Policy

### Feature Requests

1. Open an issue with the `enhancement` label
2. Describe the problem you're solving
3. Propose a solution with implementation details
4. Be open to feedback and discussion

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes following our coding standards
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation if needed
7. Submit a pull request

## Coding Standards

### Go Standards

- Follow standard Go conventions
- Use `go fmt` before committing
- Run `go vet` to catch common issues
- Add documentation comments to exported functions

### Commit Messages

Use conventional commits format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

Example:
```
feat(analyzer): add credential pattern detection

- Detect API keys in skill definitions
- Detect environment variable references
- Add tests for new patterns
```

### Testing

- Add unit tests for new functionality
- Ensure existing tests pass
- Run tests with coverage:
  ```bash
  go test -v -cover ./...
  ```

## Review Process

1. All submissions require review
2. Address review feedback promptly
3. Be responsive to questions
4. Keep changes focused and atomic

## Security Considerations

When contributing security-related changes:

- Never commit secrets or credentials
- Follow secure coding practices
- Report security issues privately
- Be mindful of potential attack vectors

## Getting Help

- Open a discussion for questions
- Join our community channel (if available)
- Check existing documentation

## Branch Strategy

### Branch Types

| Branch | Purpose | Protected |
|--------|---------|-----------|
| `main` | Development, default branch | Yes |
| `release` | Stable releases | Yes |
| `feature/*` | New features | No |
| `fix/*` | Bug fixes | No |
| `hotfix/*` | Emergency fixes | No |

### Branch Protection Rules

For `main` and `release` branches, the following rules are enforced:

1. **Require pull request reviews** - At least 1 approval required
2. **Require status checks** - CI must pass before merging
3. **Require branch up to date** - Branch must be rebased on latest
4. **Include administrators** - Rules apply to all, including admins
5. **Allow force pushes** - Disabled

### Workflow

```
main (development)
  |
  +-- feature/xyz --> PR --> Code Review --> CI Checks --> Merge
  |
release (stable releases)
  |
  +-- cherry-pick from main --> PR --> Merge --> Release Build
```

### Creating a Release

Releases are created automatically via GitHub Actions when:

1. A tag is pushed: `git tag v0.1.0 && git push origin v0.1.0`
2. Code is merged to `release` branch
3. Manual trigger via workflow dispatch

### Version Bumping

Version is auto-calculated from commit messages:

| Commit Type | Version Bump |
|-------------|---------------|
| `feat:` | Minor (x.1.0) |
| `fix:` | Patch (x.x.1) |
| `BREAKING CHANGE:` | Major (1.0.0) |

---

## Recognition

Contributors will be acknowledged in the project documentation and release notes (with permission).