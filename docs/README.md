# SkillGuard documentation

[Project overview](../README.md) / Documentation

Choose an installation or integration first, then follow the relevant contract and
validation record. Scanning, assessment and execution are separate layers.

## Install and use

| Guide                                                 | Use it when                                                                    |
| ----------------------------------------------------- | ------------------------------------------------------------------------------ |
| [CLI quick start](../README.md#cli-quick-start)       | Scanning local skills or documentation, or producing CI reports                |
| [Native plugins](native-plugins.md)                   | Adding advisory scanning to ordinary Claude Code, Codex or OpenCode sessions   |
| [Protected launchers and MCP](client-integrations.md) | Restricting a client's native executors and connecting protected action tools  |
| [Harness integration](harness-integration.md)         | Deploying a controlled execution gate in an operator-provided isolated runtime |

The native plugin preserves ordinary coding tools. Protected launchers restrict them.
Registering an MCP scanner or asking an agent to scan does not enforce use.

## Understand the contracts

| Guide                                               | Covers                                                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------- |
| [Supply-chain protections](agent-supply-chain.md)   | Threat model, delivered layers and mitigation limits                      |
| [Command extraction](command-extraction.md)         | Supported inputs and command syntax, references, limits and coverage gaps |
| [Reference verification](reference-verification.md) | Explicit registry/DNS policy, disclosure boundaries and uncertainty       |
| [Action assessment](action-assessment.md)           | Versioned requests, policies, decisions, reviews and context bindings     |
| [Architecture](../ARCHITECTURE.md)                  | Components, data flow and trust boundaries                                |

## Check validation scope

- [Native plugin validation](native-plugin-validation.md): package installation, runtime
  integrity, actual scan results and preservation of ordinary tools.
- [Protected launcher validation](client-integration-validation.md): actual MCP scans
  and assessments, executor denial and hostile startup configuration probes.
- [Release verification](../VERIFICATION.md): release checksums and container
  signatures.

Validation records name tested versions and limits. Retest when changing clients,
permissions, runtime pins or plugin combinations.

## Contribute and maintain

- [Development](../DEVELOPMENT.md): local setup and checks.
- [Contributing](../CONTRIBUTING.md): contribution requirements.
- [Security policy](../SECURITY.md): vulnerability reporting.
- [Roadmap](../ROADMAP.md): planned work.
