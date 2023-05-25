# Elastic Agent Policy Format

The policy of an Agent is the user-controlled portion of the Agent configuration that, together with [component spec files](component-specs.md), determines the components that Agent runs and their configuration.

The policy is specified in YML, and the basic layout is:

```yml
outputs:
  outputName1:
    type: <otype1>
    ...
  outputName2:
    type: <otype2>
    ...
inputs:
  - type: <itype1>
    ...
  - type: <itype2>
    ...
```

Each output configuration is grouped under the output name, while input configurations appear in a list directly under the root `inputs` field.

For the most part, each input and output configuration is passed directly to the underlying component when Agent runs it. However, a few configuration fields have special meanings or are modified by Agent, as detailed below.

The following sections list the fields within input and output configurations that are handled specially by Agent. Fields not listed here are passed through unchanged. Fields marked "removed" are only used by agent and are removed from the output configuration.

## Input fields

The following fields within input configurations are handled specially by Agent:

### `type` (string, required)

The type of the input. This must match the `name` or `aliases` field in component's [input specification](component-specs.md). If the given `type` is an alias, Agent replaces it with its canonical input type (the `name` field in the spec file).

### `id` (string)

The ID for this input. Each input must have a unique ID, which is used in logging and event metadata. This parameter _should_ be specified, but if it isn't present it defaults to the input type (note that this will be the canonical type, which may be different than the `type` field when using an alias).

### `use_output` (string, removed)

The output this input should write to. This must match one of the output names from the same policy. Defaults to `default`.

### `log_level` (string, removed)

The log level for this component. This field is not passed on to the underlying component; instead, Agent implements log level filtering itself. Possible values:
- `error`
- `warn` / `warning`
- `info`
- `debug`
- `trace`

### `policy.revision` (string, overwritten)

If the overall policy has a `revision` field (inserted by Fleet to track policy changes), its value is copied into the input's `policy.revision` field. This allows individual inputs (like Endpoint) to detect policy changes more easily.

### shipper-specific fields

The _input_ units of a shipper component have the following fields injected into their configuration:



## Output fields

### `enabled` (boolean, removed)

If present, this field determines whether the output is active. Defaults to true.

### `use_shipper` (boolean, removed)

If present, this field determines whether this output should be implemented by a Shipper component. 

### `type` (string)

The output type. If  This value must match one of the entries in the `outputs` field for its inputs

### shipper-specific fields

The _output_ unit of a component that writes to a shipper has the following fields injected into its configuration:
