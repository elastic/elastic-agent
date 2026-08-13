#!/usr/bin/env python3
"""
Backfill the 'since' version data for EDOT Collector components in components.yml.

Walks all v9.x release tags oldest-to-newest, reads internal/edot/go.mod at each
tag, and determines the first release where each component appeared. Writes the
result to the 'since' section of internal/edot/components.yml.

Run once from docs/scripts/update-docs/:
    python3 backfill-component-since.py
"""

import re
import subprocess
import sys
from pathlib import Path

import yaml

COMPONENTS_YAML = Path(__file__).parent / '../../../internal/edot/components.yml'

COMPONENTS_TYPE = ['receiver', 'connector', 'processor', 'exporter', 'extension', 'provider']
SPECIAL_COMPONENTS = ['go.opentelemetry.io/ebpf-profiler']


def run_git(*args):
    result = subprocess.run(['git'] + list(args), capture_output=True, text=True, check=True)
    return result.stdout


def get_release_tags():
    """Return all v9.MINOR.PATCH tags sorted oldest to newest."""
    output = subprocess.run(
        "git tag --list 'v9.*' | grep -E '^v[0-9]+\\.[0-9]+\\.[0-9]+$' | sort -V",
        shell=True, capture_output=True, text=True, check=True,
    ).stdout
    return [t.strip() for t in output.strip().split('\n') if t.strip()]


def read_at_tag(path, tag):
    """Read a file at a git tag. Returns None if the path doesn't exist at that tag."""
    try:
        return run_git('show', f'{tag}:{path}')
    except subprocess.CalledProcessError:
        return None


def parse_version(tag):
    m = re.match(r'^v(\d+)\.(\d+)\.(\d+)$', tag)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def gomod_path(tag):
    v = parse_version(tag)
    return 'internal/edot/go.mod' if (v and v >= (9, 0, 0)) else 'go.mod'


def extract_name(line):
    """Extract the component name from a go.mod require line."""
    line = line.strip()
    name = line[line.rfind('/') + 1 : line.rfind(' ')].strip()
    if 'ebpf-profiler' in line:
        name = 'profiling'
    return name


def components_at_tag(tag):
    """Return the set of component names present in go.mod at the given tag."""
    content = read_at_tag(gomod_path(tag), tag)
    if not content:
        return set()
    names = set()
    for line in content.splitlines():
        if line.endswith('// indirect') or '=>' in line:
            continue
        if any(f'/{t}/' in line for t in COMPONENTS_TYPE) or \
                any(s in line for s in SPECIAL_COMPONENTS):
            name = extract_name(line)
            if name:
                names.add(name)
    return names


def build_since_block(since_map):
    lines = [
        '',
        '# Component version introduction',
        '#',
        '# Records the first Elastic Agent release where each component was introduced.',
        '# Used to populate the "Added in" column in the components documentation table.',
        '# Automatically updated by the update-docs workflow on each new release.',
        '#',
        'since:',
    ]
    for name in sorted(since_map):
        lines.append(f'  {name}: {since_map[name]}')
    return '\n'.join(lines) + '\n'


def update_components_yml(since_map):
    path = COMPONENTS_YAML.resolve()
    content = path.read_text()

    inner = '\n'.join(f'  {n}: {v}' for n, v in sorted(since_map.items()))

    if re.search(r'^since:', content, re.MULTILINE):
        content = re.sub(
            r'^since:.*?(?=\n\S|\Z)',
            'since:\n' + inner,
            content,
            flags=re.MULTILINE | re.DOTALL,
        )
    else:
        content = content.rstrip('\n') + '\n' + build_since_block(since_map)

    path.write_text(content)
    print(f'\nWritten since data ({len(since_map)} entries) to {path}')


def main():
    tags = get_release_tags()
    if not tags:
        print('No v9.x release tags found.', file=sys.stderr)
        sys.exit(1)

    print(f'Found {len(tags)} release tags: {tags[0]} … {tags[-1]}\n')

    # Preserve any manually set entries that already exist
    existing = {}
    try:
        data = yaml.safe_load(COMPONENTS_YAML.read_text())
        existing = data.get('since') or {}
        if existing:
            print(f'Preserving {len(existing)} existing since entries from components.yml\n')
    except FileNotFoundError:
        pass

    first_seen = dict(existing)

    for tag in tags:
        comps = components_at_tag(tag)
        new = sorted(c for c in comps if c not in first_seen)
        if new:
            for name in new:
                first_seen[name] = tag
            print(f'{tag}: +{len(new)}  {new}')

    print(f'\nTotal: {len(first_seen)} components tracked')
    update_components_yml(first_seen)


if __name__ == '__main__':
    main()
