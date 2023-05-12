# Spec files for agent-managed binaries and services

Spec files are YML files that describe the capabilities of a binary or service and when / how to run it. They are used by Agent to convert a user-provided policy into a configured running process.

[This documentation should be expanded]()

## Preventions

Inputs may include a `runtime.preventions` section containing [EQL conditions](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html#eql-syntax-conditions) which should prevent the use of that input if any are true. Each prevention should include a `condition` in EQL syntax and a `message` that will be displayed if that condition prevents the use of this input.

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
- `runtime.major`, `runtime.minor`: the operating system version
- `user.root`: true if Agent is being run with root / administrator permissions.
