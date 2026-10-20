# Native plugin validation

Validated on macOS with Python 3.14, 20 October 2026:

| Client | Version | Native discovery/install | Real MCP scan received | Ordinary shell command preserved |
| --- | --- | --- | --- | --- |
| Claude Code | 2.1.304 | Local marketplace, native install/cache | Yes | Yes |
| Codex | 0.163.0 | Native marketplace add and plugin add/cache | Yes | Yes |
| OpenCode | 2.1.0 | Native package manager, pinned Git subdirectory package | Yes | Yes |

The shared runtime was installed from the published v0.13.0 macOS arm64 archive,
verified against the digest committed in the plugin lock, then checked against
its real MCP initialize/tools/list responses. Plugin startup makes no downloads.
The native plugin package is version 0.1.0.

`integrations/plugins/smoke.py` uses installed clients with a loopback scripted
model. It checks actual SkillGuard tool results and then runs a harmless touch
command in a temporary workspace. The marker must appear: the standard plugin
must preserve ordinary coding tools rather than silently applying strict mode.
No packages from the scanned documentation are installed, and no paid model
inference is used. Native plugin installation fetches the explicitly selected
Git package; runtime setup downloads the pinned engine archive. Clients also use
normal caches/logs. This is not a network-isolation test.

Claude uses a temporary `CLAUDE_CONFIG_DIR`, performs native marketplace
installation and uninstallation, and permits the exact plugin-namespaced MCP
tool. Codex uses its real installed plugin, disables unrelated plugins for that
test invocation and preserves user configuration. OpenCode uses a private
standalone test config pointing at the exact Git package installed by its native
package manager. A separate local-directory package test also passed.

Native remove/reinstall operations were exercised for the newly added plugin;
no unrelated plugins were removed. Current installed versions remain available
after testing. Future plugin releases and client upgrades require retesting.

Offline unit contracts cover corrupt archives, traversal/symlink/duplicate binary
rejection, altered executable/receipt rejection, failed-download preservation,
workspace cache rejection, HTTPS redirect restrictions, startup without downloads,
versioned cache selection and truthful advisory status. Node contracts verify
that OpenCode adds direct MCP wiring and commands without changing other tools
or servers. Claude's native manifest validator reports no warnings. The standalone
Skill Creator validator was unavailable because its PyYAML dependency is absent;
Native manifest checks and manual review of the short skill frontmatter were used without installing packages.

Run the offline contracts:

```sh
python3 -I -m unittest discover -s integrations/plugins -p 'test_*.py' -v
node --test integrations/plugins/test_opencode.mjs
```

After native installation/runtime setup, run the real-client checks:

```sh
python3 -I integrations/plugins/smoke.py \
  --opencode-package 'github:OSSAfrica/skillguard#4a5108c85d40def32cde720d094b2afce2f6433e::path:plugins/skillguard'
```

Use `--client claude`, `--client codex` or `--client opencode` to select one agent.
Tests are noninteractive. Interactive UI, all host/plugin combinations and Windows
or Linux native-client behavior are not certified by this macOS record. Published
engine artifacts exist for six platforms; that is separate from client testing.

The standard plugin does not install enforcement hooks, configured assessment or
an isolated install executor. No scan response grants execution permission. The
[restricted launcher validation](client-integration-validation.md) covers the
separate profiles that remove native execution paths.
