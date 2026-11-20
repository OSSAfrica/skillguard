#!/usr/bin/env python3
"""Verified, explicit runtime setup for the native SkillGuard plugin.

Only setup downloads. Status and MCP startup never fetch or run installers.
This standard plugin is advisory; it does not enforce the host's other tools.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import urllib.error
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

LIMIT = 64 * 1024 * 1024
ROOT = Path(__file__).resolve().parent


class Unavailable(Exception):
    pass


def read_regular(path, limit=LIMIT):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Unavailable("invalid_runtime_file")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise Unavailable("runtime_file_limit")
        return data


def selection():
    lock = json.loads(read_regular(ROOT / "runtime-lock.json", 65536))
    system = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "amd64": "amd64", "x86_64": "amd64"}.get(platform.machine().lower())
    selected = lock["platforms"].get(str(system) + "_" + str(arch))
    if not selected:
        raise Unavailable("unsupported_platform")
    return lock, selected


def location(cache, lock, selected):
    base = (Path(cache).expanduser() if cache else Path.home() / ".local/share/skillguard/plugin-runtime").resolve()
    cwd = Path.cwd().resolve()
    if base == cwd or cwd in base.parents:
        raise Unavailable("runtime_cache_inside_workspace")
    directory = base / ("v" + lock["version"]) / selected["platform"]
    if directory.resolve() != directory:
        raise Unavailable("runtime_cache_symlink")
    return directory


def payload(data, selected):
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != selected["sha256"]:
        raise Unavailable("archive_integrity_failed")
    binary = None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            path = PurePosixPath(member.name)
            if index >= 100 or path.is_absolute() or ".." in path.parts or "\\" in member.name or not (member.isfile() or member.isdir()) or member.size > LIMIT:
                raise Unavailable("unsafe_archive")
            if member.name == selected["binary"]:
                if binary is not None or not member.isfile():
                    raise Unavailable("ambiguous_binary")
                source = archive.extractfile(member)
                if source is None:
                    raise Unavailable("missing_binary")
                binary = source.read(LIMIT + 1)
                if len(binary) > LIMIT:
                    raise Unavailable("binary_limit")
    if binary is None:
        raise Unavailable("missing_binary")
    return binary


def installed(directory, selected):
    # Derive the executable digest from the pinned archive on every startup;
    # a writable receipt cannot bless a changed executable.
    expected = payload(read_regular(directory / selected["asset"]), selected)
    binary = directory / selected["binary"]
    actual = read_regular(binary)
    if hashlib.sha256(expected).digest() != hashlib.sha256(actual).digest():
        raise Unavailable("binary_integrity_failed")
    return binary


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com"):
            raise Unavailable("untrusted_download_redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(lock, selected):
    url = "https://github.com/OSSAfrica/skillguard/releases/download/v" + lock["version"] + "/" + selected["asset"]
    opener = urllib.request.build_opener(HTTPSRedirects())
    request = urllib.request.Request(url, headers={"User-Agent": "skillguard-native-plugin/0.1.0"})
    with opener.open(request, timeout=30) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise Unavailable("download_limit")
    return data


def atomic_write(path, data, mode):
    if path.is_symlink():
        raise Unavailable("runtime_file_symlink")
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as staged:
        temporary = Path(staged.name)
        staged.write(data)
    try:
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def health(binary):
    messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "skillguard-native-plugin", "version": "0.1.0"}}}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
    result = subprocess.run([str(binary), "mcp"], input="".join(json.dumps(m) + "\n" for m in messages), capture_output=True, text=True, timeout=10, check=False)
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise Unavailable("mcp_health_failed")
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    tools = next((r.get("result", {}).get("tools", []) for r in replies if r.get("id") == 2), [])
    if "skillguard_scan_document" not in {t.get("name") for t in tools}:
        raise Unavailable("scan_tool_missing")


def versions(lock):
    package = json.loads(read_regular(ROOT / "package.json", 65536))
    return {"plugin_version": package["version"], "pinned_engine_version": lock["version"],
            "update_instructions": "Update the plugin through its host (OpenCode: use a newly reviewed commit), run setup, then restart the agent. Updating a standalone CLI does not update this pinned runtime."}


def running_version(binary):
    result = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=10, check=False)
    match = re.fullmatch(r"skillguard version (\d+\.\d+\.\d+)\s*", result.stdout)
    if result.returncode != 0 or not match:
        raise Unavailable("runtime_version_unavailable")
    return match.group(1)


def status(binary, lock):
    health(binary)
    running = running_version(binary)
    if running != lock["version"]:
        raise Unavailable("runtime_version_mismatch")
    return {**versions(lock), "running_engine_version": running, "runtime_health": "ready", "mcp_connection": "not_checked","schema_version": 1, "status": "ready", "engine_version": lock["version"], "integrity_verified": True, "scan_available": True, "assessment_configured": False, "install_tool_available": False, "hook_state": "not_installed", "enforcement": "advisory", "execution_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("setup", "status", "mcp"))
    parser.add_argument("--cache-dir", help="Operator-selected cache outside the target; default user data directory")
    parser.add_argument("--archive", help="Offline release archive, setup only; must match the packaged pin")
    args = parser.parse_args()
    lock = None
    try:
        if args.archive and args.operation != "setup":
            raise Unavailable("archive_only_for_explicit_setup")
        lock, selected = selection()
        directory = location(args.cache_dir, lock, selected)
        if args.operation == "setup":
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            directory.chmod(0o700)
            data = read_regular(Path(args.archive)) if args.archive else download(lock, selected)
            binary_data = payload(data, selected)
            # Verify before replacing anything; rejected downloads preserve the
            # previous installation. Startup sees either a matching pair or fails.
            atomic_write(directory / selected["asset"], data, 0o600)
            atomic_write(directory / selected["binary"], binary_data, 0o700)
        binary = installed(directory, selected)
        if args.operation == "mcp":
            os.execv(str(binary), [str(binary), "mcp"])
        print(json.dumps(status(binary, lock)))
        return 0
    except (Unavailable, OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.TimeoutExpired) as error:
        reason = "runtime_check_failed"
        if isinstance(error, Unavailable):
            reason = str(error)
        elif isinstance(error, FileNotFoundError):
            reason = "runtime_file_missing"
        elif isinstance(error, PermissionError):
            reason = "runtime_permission_denied"
        elif isinstance(error, subprocess.TimeoutExpired):
            reason = "runtime_health_timeout"
        elif isinstance(error, urllib.error.URLError):
            reason = "runtime_download_failed"
        recovery = {
            "runtime_cache_inside_workspace": "Launch the agent from the project directory rather than an ancestor of the runtime cache, or select an operator-managed cache outside the target.",
            "runtime_file_missing": "Run setup for this installed plugin, then restart the agent.",
            "runtime_download_failed": "Check HTTPS access to GitHub releases, or supply the exact pinned archive with --archive.",
            "archive_integrity_failed": "The archive does not match the packaged pin. Obtain the exact reviewed release; do not change the checksum to bypass verification.",
        }.get(reason, "Inspect the local runtime configuration and permissions, run setup/status again, and restart after successful setup.")
        result = {"reason": reason, "next_step": recovery, "runtime_health": "unavailable", "mcp_connection": "not_checked","schema_version": 1, "status": "unavailable", "enforcement": "advisory", "scan_available": False, "execution_authorized": False}
        if lock is not None:
            try:
                result.update(versions(lock))
            except (OSError, ValueError, KeyError, TypeError):
                pass
        print(json.dumps(result), file=sys.stderr if args.operation == "mcp" else sys.stdout)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
