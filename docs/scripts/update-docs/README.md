# EDOT Collector docs automation scripts

This directory contains automation scripts for generating and updating EDOT Collector documentation.

## Overview

The `update-components-docs.py` script automatically generates documentation content based on:

- **Component data** from `go.mod` (dependencies)
- **Component metadata** from `components.yml` (core/deprecated status, annotations)
- **Documentation mappings** from `component-docs.yml` (links to docs pages)

## How it works

### Data flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Git Tags      │     │   components.yml │     │ component-docs  │
│   (go.mod)      │     │   (metadata)     │     │     .yml        │
└────────┬────────┘     └────────┬─────────┘     └────────┬────────┘
         │                       │                        │
         └───────────────────────┼────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ update-components-docs │
                    │         .py            │
                    └────────────┬───────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  components.md  │   │ default-config-  │   │  custom-         │
│  (table)        │   │ standalone.md    │   │  collector.md    │
└─────────────────┘   └──────────────────┘   └──────────────────┘
```

### Tagged sections

The script updates content between special markers in markdown files:

```markdown
% start:edot-collector-components-table
... auto-generated content ...
% end:edot-collector-components-table
```

**Available tags:**

| Tag | Description |
|-----|-------------|
| `edot-collector-components-table` | Component table in `components.md` |
| `edot-collector-components-ocb` | OCB config in `custom-collector.md` |
| `edot-gateway-9x-table` | Gateway links for 9.x versions |
| `edot-gateway-8x-table` | Gateway links for 8.x versions |
| `edot-samples-links` | Sample configuration reference links |

### Path migrations

The script handles path changes between versions using semantic version comparison:

| Path Type | Old Path (< 9.3) | New Path (≥ 9.3) |
|-----------|------------------|------------------|
| components.yml | `internal/pkg/otel/components.yml` | `internal/edot/components.yml` |
| samples | `internal/pkg/otel/samples/` | `internal/edot/samples/` |
| go.mod | `go.mod` (root) | `internal/edot/go.mod` |

Path resolution uses semantic versioning for fast lookups without subprocess calls.

## Usage

### Generate documentation

```bash
cd docs/scripts/update-docs
python update-components-docs.py
```

### Check if documentation is up-to-date

```bash
cd docs/scripts/update-docs
python update-components-docs.py check
```

### Specify a version

```bash
LATEST_VERSION=9.2.2 python update-components-docs.py
```

## Templates

Templates use Jinja2 syntax and are located in `templates/`:

| Template | Purpose |
|----------|---------|
| `components-table.jinja2` | Component table with footnotes |
| `gateway-table.jinja2` | Version-specific gateway links |
| `samples-links.jinja2` | Sample configuration reference links |
| `ocb.jinja2` | OpenTelemetry Collector Builder config |

## Configuration files

### `components.yml`

Located at `internal/edot/components.yml`, defines:

```yaml
core_components:
  - filelogreceiver
  - hostmetricsreceiver
  # ...

deprecated:
  - elasticinframetricsprocessor
  - elastictraceprocessor

annotations:
  elasticinframetricsprocessor:
    comment: |
      Deprecated in 9.1.0. Refer to [Migrate from deprecated components]...
```

### `component-docs.yml`

Located at `docs/reference/edot-collector/component-docs.yml`, maps components to documentation pages:

```yaml
components:
  filelogreceiver:
    doc_path: /reference/edot-collector/components/filelogreceiver.md
```

## Adding a new path migration

When files move between versions:

1. Add entry to `PATH_MIGRATIONS` in the script:

```python
PATH_MIGRATIONS = {
    'new_path_type': {
        'new': 'internal/edot/new/path',
        'old': 'internal/pkg/otel/old/path',
        'since': (9, 4, 0),  # Version where change occurs
    },
}
```

2. Create convenience function if needed:

```python
def get_new_path_for_tag(tag):
    return resolve_path_for_tag(tag, 'new_path_type')
```

## Testing

Run the unit tests:

```bash
cd docs/scripts/update-docs
python -m pytest test_update_components_docs.py -v
```

## CI/CD Integration

The `.github/workflows/validate-docs-structure.yml` workflow:

1. Triggers on changes to `internal/edot/**` or `docs/scripts/update-docs/**`
2. Runs `mage check:docsFiles` to validate required files exist
3. Ensures documentation can be generated for future releases

## Troubleshooting

### "Could not read components file from tag"

The `components.yml` file was added in v9.2.1. Earlier versions don't have this file, and the script will use default values.

### Path resolution returns wrong path

Check that `PATH_MIGRATIONS` has correct version thresholds. Use `parse_version_tag()` to verify version parsing:

```python
from update_components_docs import parse_version_tag
print(parse_version_tag('v9.2.2'))  # (9, 2, 2)
```

