# Elastic Agent Policies

The policy of an Agent is the user-controlled portion of the Agent configuration that, together with [component spec files](component-specs.md), determines the components that Agent runs and their configuration.

A __component__ is an executable that Agent runs or monitors. That component is divided into __units__ corresponding to its functional behavior. For example, Filebeat is a component, but Filebeat may be run with multiple `filestream` inputs, and each of those is a unit with its own configuration.

Components run by Agent have one or more input units describing the data they collect, and one output unit describing where the data goes.

## Example: policies mapped to running processes

Here is an example policy, and a diagram of the resulting components.

```yml
version: 2
outputs:
  elasticsearch1.type: "elasticsearch"
  elasticsearch2.type: "elasticsearch"
  logstash.type: "logstash"
inputs:
  - type: filestream
    id: filestream-1
    use_output: elasticsearch1
    ...
  - type: filestream
    id: filestream-2
    use_output: elasticsearch1
    ...
  - type: metrics
    id: metrics-1
    use_output: elasticsearch1
    ...
  - type: metrics
    id: metrics-2
    use_output: elasticsearch1
    ...
  - type: udp
    id: udp-1
    use_output: logstash
    ...
  - type: endpoint
    id: endpoint-1
    use_output: elasticsearch2
```

![Example deployment without shipper](diagrams/components-example.svg)

In this example, we have defined three outputs: `elasticsearch1`, `elasticsearch2`, and `logstash`. We have also defined 6 total inputs, four writing to `elasticsearch1` and one each writing to `elasticsearch2` and `logstash`.

Agent has divided these inputs among four running processes according to their type. Each running process is one component. Each component has an output unit that sends its data to the appropriate destination, and some number of input units that provide data to the output.

In this example there are four __components__. The `filebeat1` component has three __units__, two input and one output.

![Example deployment with shipper](diagrams/components-shipper-example.svg)

This example shows the same scenario, but with the shipper enabled. In this setup, there are shipper components whose job is to send the data upstream, and input components that send their data to a local shipper rather than managing their own independent queue and network connections.

A shipper component also has one output unit and one or more input units, but its input units correspond to the components that write to it rather than to individual data sources.

In this example there are _seven_ components, as Agent has created three shippers to manage the connections to each of the three outputs. The `shipper1` component has two input units, since it receives data from both `filebeat1` and `metricbeat` (with two individual data sources each). All this data is queued by the shipper and forwarded upstream to `elasticsearch1`.

## Agent policy format

The policy is specified in YML, and the basic layout is:

```yml
outputs:
  outputName1:
    type: <output type 1>
    ...
  outputName2:
    type: <output type 2>
    ...
inputs:
  - type: <input type 1>
    id: <input id 1>
    ...
  - type: <input type 2>
    id: <input id 2>
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


## Output fields

### `enabled` (boolean, removed)

If present, this field determines whether the output is active. Defaults to true.

### `type` (string, required)

The output type. If `use_shipper` is `false`, this value must match one of the entries in the `outputs` field for its inputs' spec files. Otherwise, the `shippers` field for its inputs' spec file must include a shipper type that supports this output. See [Component Specs](component-specs.md) for more details.

### `use_shipper` (boolean, removed)

If present, this field determines whether this output should be implemented by a Shipper component. Defaults to false.

### `log_level` (string, removed)

The log level for this component. This field is not passed on to the underlying component; instead, Agent implements log level filtering itself. Possible values:
- `error`
- `warn` / `warning`
- `info`
- `debug`
- `trace`

### `headers` (`map[string]string`)

Agent does not use this field itself, however if the output's `type` is `elasticsearch` then Agent will insert any headers it acquired during Fleet enrollment into this field.


## Shipper-specific fields

When components use the shipper, it results in units that don't correspond directly to a configuration entry in the policy. A component that writes to the shipper will be given an output unit that targets the shipper, and a shipper component will be given input units detailing the components that will connect to it.

### Shipper output fields

The output unit of a component that writes to a shipper is given the following configuration:

- `type` (string): the shipper type
- `server` (string): the connection address of the shipper (a named socket on Darwin/Linux, a named pipe on Windows)
- `ssl.certificate_authorities` (string list): a list consisting of one element, which is the certificate authority the shipper will use to verify clients that connect to it. Each shipper instance is assigned its own unique certificate authority on startup.
- `ssl.certificate` (string): the certificate to present when connecting to the shipper, signed by the CA in `ssl.certificate_authorities`.
- `ssl.key` (string): the key for `ssl.certificate`

### Shipper input fields

For each component that writes to a shipper, the shipper will be given an input unit with the following configuration:

- `id` (string): the id of the input unit, which is also the id of the originating component.
- `type` (string): the shipper type.
- `units` (list): a list of all configuration units in the originating component, with each containing:
  * `id` (string): the unit id
  * `config`: the full configuration tree for that unit
- `server` (string): the address the server should listen on for connections from this component (a named socket on Darwin/Linux, a named pipe on Windows). The value of `server` is the same for all units.
- `ssl.certificate_authorities` (string list): a list with one entry, which is this shipper's assigned certificate authority. The value of `ssl.certificate_authorities` is the same for all units. Clients connecting to the shipper will present certificates signed by this CA.
- `ssl.certificate` (string): the certificate this component will present when connecting to the shipper.
- `ssl.key` (string): the private key for the client component's certificate `ssl.certificate`.


# How agent policies map to running processes

