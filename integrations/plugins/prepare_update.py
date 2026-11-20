#!/usr/bin/env python3
"""Prepare a reviewable plugin update from one published release's checksum file."""
import argparse
import base64
import json
from pathlib import Path
import re

from pin_runtime import generate

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ['plugins/skillguard/package.json', 'plugins/skillguard/plugin.json',
             'plugins/skillguard/.claude-plugin/plugin.json', 'plugins/skillguard/.codex-plugin/plugin.json']
MARKETPLACES = ['.claude-plugin/marketplace.json']


def prepare(root, engine_version, checksum_text):
    lock = generate(engine_version, checksum_text)  # Validate all six pins before writing.
    plugin = root / 'plugins/skillguard'
    old = json.loads((plugin / 'runtime-lock.json').read_text())
    if old == lock:
        return False
    if tuple(map(int, engine_version.split('.'))) <= tuple(map(int, old['version'].split('.'))):
        raise ValueError('Runtime updates must advance the engine version')
    current = json.loads((plugin / 'package.json').read_text())['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', current):
        raise ValueError('Invalid plugin version')
    major, minor, patch = map(int, current.split('.'))
    new_version = f'{major}.{minor}.{patch + 1}'
    changes = {}
    for name in MANIFESTS:
        data = json.loads((root / name).read_text())
        if data['version'] != current:
            raise ValueError('Plugin manifests disagree')
        data['version'] = new_version
        changes[name] = data
    for name in MARKETPLACES:
        data = json.loads((root / name).read_text())
        for item in data['plugins']:
            if item['name'] == 'skillguard':
                if item['version'] != current:
                    raise ValueError('Marketplace version disagrees')
                item['version'] = new_version
        changes[name] = data
    changes['plugins/skillguard/runtime-lock.json'] = lock
    for name, data in changes.items():
        (root / name).write_text(json.dumps(data, indent=2) + '\n')
    return True


def commit_request(root, repository, branch, expected_head, version):
    if not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release tag')
    names = MANIFESTS + MARKETPLACES + ['plugins/skillguard/runtime-lock.json']
    additions = [{'path': name, 'contents': base64.b64encode((root/name).read_bytes()).decode('ascii')} for name in names]
    return {
        'query': 'mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid signature { isValid } } } }',
        'variables': {'input': {
            'branch': {'repositoryNameWithOwner': repository, 'branchName': branch},
            'expectedHeadOid': expected_head,
            'message': {'headline': f'chore(plugins): pin reviewed runtime {version}',
                        'body': 'Signed-off-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>'},
            'fileChanges': {'additions': additions},
        }},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--checksums')
    parser.add_argument('--commit-request')
    parser.add_argument('--repository')
    parser.add_argument('--branch')
    parser.add_argument('--expected-head')
    args = parser.parse_args()
    if args.commit_request:
        request = commit_request(ROOT, args.repository, args.branch, args.expected_head, 'v'+args.version)
        Path(args.commit_request).write_text(json.dumps(request)+'\n')
    else:
        if not args.checksums:
            parser.error('--checksums is required when preparing an update')
        prepare(ROOT, args.version, Path(args.checksums).read_text())


if __name__ == '__main__':
    main()
