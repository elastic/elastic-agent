# Diagnostics Bundle Layout

The bundle layout — top-level files, `state.yaml` structure, log files and fields, `components/`, `edot/`, and what a missing file means — is documented in [docs/diagnostics.md](../../../../docs/diagnostics.md). This page only adds what's useful when analyzing a bundle.

## Analysis notes

- `components-expected.yaml` and `components-actual.yaml` contain compiled component definitions (binary path, spec and units), not the `state.yaml` component-state schema. Unit configurations are omitted; inspect `computed-config.yaml` instead. In `components-*.yaml` a unit's type is a `UnitType` integer: `0` = INPUT, `1` = OUTPUT; in `state.yaml` it is the key prefix (`input-<id>` / `output-<id>`).
- A new log file starts on rotation or process restart: the un-suffixed file is the **oldest** of the day, then `-1`, `-2`, …. Concatenate and sort by `@timestamp` rather than relying on names.
- `beat_metrics.json` top-level keys: `libbeat.pipeline.events`, `libbeat.output`, `libbeat.config`, `system.cpu`, `system.load`; `registry.tar.gz` extracts to `registry/filebeat/{log,meta}.json`.
- Profiles are readable directly by `go tool pprof`: agent-process profiles at the bundle root, EDOT collector profiles in `edot/*.profile.gz`.
- `edot/otel-merged-actual.yaml` can differ from the top-level `otel-merged.yaml` during a transition.
- `log.source` is the component id for captured output of a process-mode component (and absent for collector lines); `component.id` is nested (`.component.id`) on supervisor lines and flat (`.["component.id"]`) on captured process-mode output — query both.
