# Spec files for agent-managed components

Spec files are YML files that describe the capabilities of a component and when / how to run it. They are used by Agent to convert a user-provided [policy](agent-policy.md) into a configured running process.

A __component__ is an executable that Agent runs or monitors. That component is divided into __units__ corresponding to its functional behavior. For example, Filebeat is a component, but Filebeat may be run with multiple `filestream` inputs, and each of those is a unit with its own configuration. Components run by Agent have one or more input units and one output unit.

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

The `version` key must be present and must equal 2 (to distinguish from the older version 1 schema that is no longer supported). `inputs` is a list of input types this component can run, and `shippers` is a list of shipper types this component can run. Most configuration fields are shared between inputs and shippers,




[This documentation should be expanded](https://github.com/elastic/elastic-agent/issues/2690)



## Preventions

Components may include a `runtime.preventions` section containing [EQL conditions](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html#eql-syntax-conditions) which should prevent the use of that component if any are true. Each prevention should include a `condition` in EQL syntax and a `message` that will be displayed if the condition prevents the use of a component.

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
