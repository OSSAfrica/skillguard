#!/usr/bin/env python3
"""Install reviewed SkillGuard client launchers outside agent workspaces.

Does not modify Claude/Codex/OpenCode global settings or shell startup files.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--scanner", required=True)
    args = parser.parse_args()
    prefix = Path(args.prefix).resolve()
    source = Path(__file__).resolve().parents[2]
    scanner = Path(args.scanner).resolve(strict=True)
    if prefix == source or source in prefix.parents:
        parser.error("Install prefix must be outside the source/target tree")
    if prefix.exists() and any(prefix.iterdir()):
        parser.error("Select a new empty installation prefix; existing installations are not overwritten")
    prefix.mkdir(parents=True, mode=0o700, exist_ok=True)
    runtime = prefix / "runtime"
    (runtime / "integrations/clients").mkdir(parents=True)
    (runtime / "examples/harness").mkdir(parents=True)
    for name in ("launch.py",):
        shutil.copy2(source / "integrations/clients" / name, runtime / "integrations/clients" / name)
    shutil.copytree(source / "integrations/clients/opencode-plugin", runtime / "integrations/clients/opencode-plugin")
    shutil.copy2(source / "examples/harness/claude_quarantine.py", runtime / "examples/harness/claude_quarantine.py")
    shutil.copy2(source / "examples/harness/guard.py", runtime / "examples/harness/guard.py")
    binary = prefix / "skillguard"
    shutil.copy2(scanner, binary)
    binary.chmod(0o700)
    bindir = prefix / "bin"
    bindir.mkdir(mode=0o700)
    launcher = runtime / "integrations/clients/launch.py"
    python = str(Path(sys.executable).resolve())
    for client in ("claude", "codex", "opencode"):
        code = "#!" + python + "\n" + '''import argparse, hashlib, os, pathlib, sys
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--root", default=os.getcwd())
parsed, _ = parser.parse_known_args()
root = str(pathlib.Path(parsed.root).resolve())
''' + "prefix = pathlib.Path(" + repr(str(prefix)) + ")\n" + '''state = prefix / "profiles" / hashlib.sha256(root.encode()).hexdigest()[:20]
''' + "command = [" + repr(python) + ", '-I', " + repr(str(launcher)) + ", " + repr(client) + ", '--scanner', " + repr(str(binary)) + ", '--state-dir', str(state), *sys.argv[1:]]\n" + "os.execv(" + repr(python) + ", command)\n"
        path = bindir / ("skillguard-" + client)
        path.write_text(code)
        path.chmod(0o700)
    (prefix / "installation.json").write_text(json.dumps({"schema_version": 1, "source": "reviewed local installation",
        "launchers": [str(bindir / ("skillguard-" + client)) for client in ("claude", "codex", "opencode")]}, indent=2) + "\n")
    print(json.dumps({"status": "installed", "prefix": str(prefix), "launchers_directory": str(bindir),
                      "note": "Opt-in commands only. Existing agent settings and shell PATH were not changed."}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
