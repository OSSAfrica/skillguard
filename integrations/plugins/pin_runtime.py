#!/usr/bin/env python3
"""Maintainer-only lock generation from reviewed GoReleaser checksums.

The checksums input is trusted release-review evidence, never fetched by plugin
startup. Commit and review the generated lock before distributing a plugin.
"""
import argparse
import json
from pathlib import Path
import re

PLATFORMS = [os + '_' + arch for os in ('darwin','linux','windows') for arch in ('amd64','arm64')]


def generate(version, text):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Select an exact release version')
    digests = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, filename = line.split()
        if filename in digests or not re.fullmatch(r'[a-f0-9]{64}', digest):
            raise ValueError('Invalid or duplicate checksum entry')
        digests[filename] = digest
    platforms = {}
    for key in PLATFORMS:
        filename = 'skillguard_' + version + '_' + key + '.tar.gz'
        platforms[key] = {'platform':key, 'asset':filename, 'sha256':digests[filename], 'binary':'skillguard.exe' if key.startswith('windows') else 'skillguard'}
    return {'schema_version':1, 'version':version, 'platforms':platforms}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',required=True)
    parser.add_argument('--checksums',required=True)
    parser.add_argument('--output',default=str(Path(__file__).resolve().parents[2] / 'plugins/skillguard/runtime-lock.json'))
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    result = generate(args.version, Path(args.checksums).read_text())
    output = Path(args.output)
    if args.check:
        return int(json.loads(output.read_text()) != result)
    output.write_text(json.dumps(result,indent=2)+'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
