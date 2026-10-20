# Install SkillGuard as a native plugin

The standard SkillGuard plugin adds local scanning tools and setup/status/review
workflows to normal Claude Code, Codex and OpenCode sessions. You do not need Go
or a repository checkout. Python 3.10+ must be available as `python3` on PATH.

**This plugin is advisory.** It does not block the agent's other command tools,
install enforcement hooks, configure an assessment policy or authorize package
installation. For restricted execution, use the separate
[protected launcher profiles](client-integrations.md).

Start the agent in a project directory. The verified runtime cache must remain
outside that project. Review the plugin source before installing it: like other
native plugins, its code runs with your user privileges.

## Claude Code

```sh
claude plugin marketplace add OSSAfrica/skillguard
claude plugin install skillguard@ossafrica-skillguard
```

Restart Claude, then invoke:

```text
/skillguard:setup
/skillguard:status
/skillguard:review
```

The setup skill runs the installed plugin's own `runtime.py` with Python's
isolated mode. Review scans the documentation you select; it does not follow its
installation instructions. You can ask: “Use SkillGuard to review this llms.txt.”

## Codex

```sh
codex plugin marketplace add OSSAfrica/skillguard
codex plugin add skillguard@ossafrica-skillguard
```

Restart Codex. Ask it to use the SkillGuard plugin's setup skill, then its status
or review skill. These are bundled plugin skills, not instructions to find an
arbitrary setup script online. The native plugin provides its MCP tools after the
runtime is installed and the session restarts.

A repository marketplace is separate from the universal public plugin directory.
No public-directory approval is required to install this repository's plugin.
The package includes portable and Codex compatibility manifests.

## OpenCode 2

Install the reviewed package from its immutable Git commit:

```sh
opencode plugin add 'github:OSSAfrica/skillguard#4a5108c85d40def32cde720d094b2afce2f6433e::path:plugins/skillguard'
```

Restart OpenCode and invoke:

```text
/skillguard-setup
/skillguard-status
/skillguard-review
```

The plugin registers the reserved `ossafrica_skillguard_native` MCP server with
`codemode:false` so scanning is directly available. It preserves other MCP
servers, tools and permission settings. The package has no npm dependencies or
installation lifecycle scripts. It is distributed through Git; there is no npm
package users need to find or claim.

## Runtime setup and status

Setup explicitly downloads one existing SkillGuard **v0.13.0** release archive.
Its SHA-256 is pinned in the plugin's `runtime-lock.json`, covering macOS, Linux
and Windows on amd64/arm64. Only the expected regular binary is extracted;
traversal, symlinks and duplicate binaries are rejected. Corrupt downloads are
rejected before replacing the previous installation.

The cache is `~/.local/share/skillguard/plugin-runtime/v0.13.0/<platform>/`.
All three agents share it. Status and normal MCP startup never download anything.
Startup verifies the archive against the packaged pin and compares the installed
binary with that verified archive; a writable checksum receipt cannot bless an
altered executable. A missing/corrupt runtime makes scanning unavailable.

A ready status reports:

```json
{
  "status": "ready",
  "engine_version": "0.13.0",
  "integrity_verified": true,
  "scan_available": true,
  "assessment_configured": false,
  "install_tool_available": false,
  "hook_state": "not_installed",
  "enforcement": "advisory",
  "execution_authorized": false
}
```

This confirms scanning availability, not protection against every execution path.
The agent can call the scanner, but this does not automatically scan every file
or intercept every command. Static scans are offline; a clean result or package
existence does not establish package legitimacy.

For offline setup, an operator can run the installed plugin's helper:

```sh
python3 -I /absolute/path/to/installed/plugin/runtime.py setup \
  --archive /path/to/the/exact/pinned/release/archive.tar.gz
```

The archive must match the packaged platform pin. `--cache-dir` selects a cache
outside the target for operator deployments/tests. Status and MCP mode do not
accept an offline archive. Do not modify the lock to make an unknown file pass.
Restart the agent after setup so its MCP connection is recreated.

## Update and remove

Update from reviewed marketplace/package sources, then run setup/status again.
A plugin update can change its engine pin; an older installed engine does not
satisfy a new version's cache entry. Never use an unpinned “latest” engine fallback.

Claude updates with `claude plugin update skillguard@ossafrica-skillguard`.
For Codex, refresh the Git marketplace using
`codex plugin marketplace upgrade ossafrica-skillguard`, then remove/add the
plugin to install the reviewed version. OpenCode's installation above is pinned:
remove that package reference and add the newly reviewed full commit reference
to upgrade. Exact Git revisions intentionally do not float to newer code.

Remove the native plugin with:

```sh
claude plugin uninstall skillguard@ossafrica-skillguard
codex plugin remove skillguard@ossafrica-skillguard
opencode plugin remove 'github:OSSAfrica/skillguard#4a5108c85d40def32cde720d094b2afce2f6433e::path:plugins/skillguard'
```

Restart the agent afterward. Shared engine cache is retained because another
agent may still use it. Once all integrations are removed, users can delete only
`~/.local/share/skillguard/plugin-runtime` to remove that cache. Existing strict
launcher installations have a separate directory and lifecycle.

## Validation and maintenance

See [native plugin validation](native-plugin-validation.md) for actual installed
client versions, package-manager tests and scope. Runtime integrity and package
contracts run in CI; live-client tests are opt-in and use a loopback model.

Maintainers update engine pins from reviewed, version-specific GoReleaser
checksums with `integrations/plugins/pin_runtime.py`. The helper never resolves a
latest version or fetches remote checksums at agent startup. Bump all plugin
manifests together, review the new lock and repeat installed-client tests.

- [Claude plugin manifests](https://code.claude.com/docs/en/plugins-reference)
- [Official OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins)
- [OpenCode native package management](https://dev.opencode.ai/v2/docs/plugins)
