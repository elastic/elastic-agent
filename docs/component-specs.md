# Spec files for agent-managed components

Spec files are YML files that describe the capabilities of a component and when / how to run it. They are used by Agent to convert a user-provided [policy](agent-policy.md) into a configured running process.

## Spec file layout

A spec file corresponds to a specific executable, which must be in the same directory and have the same name -- for example `filebeat.spec.yml` would correspond to the executable `filebeat`, or `filebeat.exe` on Windows. The configuration is broken into sections:

```yml
version: 2
inputs:
  - name: <input name 1>
    ...
  - name: <input name 2>
    ...
shippers:
  - name: <shipper name 1>
    ...
```

The `version` key must be present and must equal 2 (to distinguish from the older version 1 schema that is no longer supported).

`inputs` is a list of input types this component can run, and `shippers` is a list of shipper types this component can run. Each configured input and shipper also has its own list of `outputs` that it supports, but the spec file only tracks the list of supported types, and the rest comes from the [Agent policy](agent-policy.md).

Most configuration fields are shared between inputs and shippers. The next section lists all valid fields, noting where there are differences between the two cases.

## Input / Shipper configuration fields

### `name` (string, required)

The name of this input or shipper. This name must be unique for each platform, however two inputs or shippers that support different platforms can have the same name. This allows the configuration to vary between platforms.

### `aliases` (list of strings, input only)

Inputs may specify a list of alternate names that policies can use to refer to them. Any occurrence of these aliases in a policy configuration will be replaced with the value of `name`.

### `description` (string, required)

A short description of this input or shipper.

### `platforms` (list of strings, required)

The platforms this input or shipper supports. Must contain one or more of the following:
- `container/amd64`
- `container/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `linux/amd64`
- `linux/arm64`
- `windows/amd64`

### `outputs` (list of strings)

The output types this input or shipper supports. If this is an input, then inputs of this type can only target (non-shipper) output types in this list. If this is a shipper, then this shipper can only implement output types in this list.

### `proxied_actions` (list of strings)

The action types that should be forwarded to the corresponding component. Inital application for this was forwarding the Agent actions such as UNENROLL and UPGRADE to Endpoint service as a part of the Agent/Endpoint tamper protection feature.

Example for Endpoint spec:
```
proxied_actions:
  - UNENROLL
  - UPGRADE
```

### `shippers` (list of strings, input only)

The shipper types this input supports. Inputs of this type can target any output type supported by the shippers in this list, as long as the output policy includes `shipper.enabled: true`. If an input supports more than one shipper implementing the same output type, then Agent will prefer the one that appears first in this list.

### `runtime.preventions`

The `runtime.preventions` field contains a list of [EQL conditions](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html#eql-syntax-conditions) which should prevent the use of this input or shipper if any are true. Each prevention should include a `condition` in EQL syntax and a `message` that will be displayed if the condition prevents the use of a component.

Here are some example preventions taken from the Endpoint spec file:

```yml
runtime:
  preventions:
    - condition: ${runtime.arch} == 'arm64' and ${runtime.family} == 'redhat' and ${runtime.major} == '7'
      message: "No support for RHEL7 on arm64"
    - condition: ${user.root} == false
      message: "Elastic Agent must be running as root"
```

The variables that can be accessed by a condition are:

- `runtime.os`: the operating system, either `"windows"`, `"darwin"`, `"linux"`, or `"container"`.
- `runtime.arch`: the CPU architecture, either `"amd64"` or `"arm64"`.
- `runtime.platform`: a string combining the OS and architecture, e.g. `"windows/amd64"`, `"darwin/arm64"`.
- `runtime.family`: OS family, e.g. `"debian"`, `"redhat"`, `"windows"`, `"darwin"`
- `runtime.major`, `runtime.minor`: the operating system version. Note that these are strings not integers, so they must be converted in order to use numeric comparison. For example to check if the OS major version is at most 12, use `number(runtime.major) <= 12`.
- `user.root`: true if Agent is being run with root / administrator permissions.

### `command` (required for shipper)

The `command` field determines how the component will be run. Shippers must include this field, while inputs must include either `command` or `service`. `command` consists of the following subfields:

#### `command.args` (list of strings)

the command-line arguments to pass to this component when running it.

#### `command.env`

A list of environment variables to set when running this component. Each entry of the list consists of `name` and `value` pairs, for example:

```yml
command:
  ...
  env:
    - name: DEBUG
      value: "true"
    - name: ELASTICSEARCH_HOST
      value: "https://127.0.0.1:9200"
```

#### `command.timeouts`

The timeout duration for various actions performed on this component:

- `checkin`: Agent checkins
- `restart`: Restarting the component
- `stop`: Stopping the component

For example:

```yml
command:
  ...
  timeouts:
    checkin: 10s
    restart: 30s
```

#### `command.log`

Agent expects commands it runs to write their logs to standard output as lines of JSON. Each log event has certain standard data like log level and timestamp, however the keys for these values may vary between different programs. `command.log` specifies the meaning of JSON log events. It has the following subfields:

- `level_key`: the JSON key for the event's log level
- `time_key`: the JSON key for the event's timestamp
- `time_format`: The format used for log timestamps. This field uses the definitions from [Golang's time formatting support](https://pkg.go.dev/time#Time.Format), which consists of providing an example string in the target format. Example values: `Mon, 02 Jan 2006 15:04:05 -0700`, `Mon Jan _2 15:04:05 MST 2006`.
- `message_key`: the JSON key for the log message
- `ignore_keys`: a list of JSON keys that should be skipped when reading log events from this command

#### `restart_monitoring_period` (duration), `maximum_restarts_per_period` (integer)

Some components (particularly Beats) terminate when they receive a new configuration that can't be applied dynamically. Ordinarily, termination of a process that is supposed to be running is considered an error. These configuration flags prevent termination from being immediately reported as failure in the UI. Agent will only report a component as failed if it restarts more than `maximum_restarts_per_period` times within `restart_monitoring_period`.

### `service` (input only)

Inputs that are run as a system service (like Endpoint Security) can use `service` instead of `command` to indicate that Agent should only monitor them, not manage their execution. `service` consists of the following subfields: 

#### `service.cport` (int, required)

The TCP port on localhost where the service listens for connections from Agent.

#### `service.log.path` (string)

The path to this service's logs directory.

#### `service.operations`  (required)

`operations` gives instructions for performing three operations: `check`, `install`, and `uninstall`. Each of these operations has its own subconfiguration with the following fields:

- `args` (identical to `command.args`): the command-line arguments to pass for this operation
- `env` (identical to `command.env`): the environment variables to set for this operation
- `timeout`: the timeout duration for this operation.

For example:

```yml
operations:
  check:
    args:
      - "verify"
      - "--verbose"
    timeout: 30
  install:
    args:
      - "install"
    env:
      - name: DEBUG
        value: "true"
    timeout: 600
  uninstall:
    args:
      - "uninstall"
    timeout: 600
```

#### `service.timeouts.checkin`

The timeout duration for checkins with this component