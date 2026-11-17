# plugin-check

Runs on PRs that change `.buildkite/**`, `catalog-info.yaml` or `renovate.json` (step ":mag: Plugin check" in `pipeline.yml`).
`generate.sh` diffs plugin pins (`org/name#vX.Y.Z` in `.buildkite/**/*.{yml,yaml,sh}` and `catalog-info.yaml`; floating refs like `#main` are reported and fail) against the PR base, then:

1. `verify-tags.sh` fails on floating refs, missing tags and draft releases, errors (never passes) when `gh` can't tell, and warns on outdated pins and version drift. Fork-tag plugins are skipped in `pins.sh`.
2. `gen-probes.sh` uploads one synthetic probe step per changed plugin.
3. `gen-dryrun.sh` uploads dry-run triggers for pipelines the main PR build does not already trigger (`coverage.tsv`; `elastic-agent-binary-dra` is deliberately excluded, see the file).

Extend it:
- **New probe**: add `probes/<org>_<plugin>.yml` (placeholders `__PIN__ __PLUGIN__ __VERSION__ __KEY__`); plugins without one get the static tag check only. Use read-only/canary secrets, never echo them.
- **New dry-run pipeline**: add a row to `coverage.tsv`. The pipeline must have a real dry-run switch (see `DRY_RUN` in `steps/helm-charts.sh`); never map one that can publish.

Tests: `bats .buildkite/scripts/plugin-check/tests/` (needs `bats`, `git`; `gh` is stubbed).
