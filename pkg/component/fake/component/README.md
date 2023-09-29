# Fake Component

Controllable through GRPC control protocol with actions. Allows tests to simulate control and communication with a running sub-process.


## How to use the fake component
If we need to use the fake component for a manual test, we need to build it using
`mage build:testbinaries`
and then we have to drop the binary and its corresponding spec file (see example below) in the
`elastic-agent-<unique suffix>/data/components` directory.

### Spec file example

```yaml
version: 2
inputs:
  - name: fake
    description: "Fake component input"
    platforms: &platforms
      - linux/amd64
      - linux/arm64
      - darwin/amd64
      - darwin/arm64
      - windows/amd64
      - container/amd64
      - container/arm64
    outputs: &outputs
      - elasticsearch
    shippers: &shippers
      - shipper
    command: &command
      restart_monitoring_period: 5s
      maximum_restarts_per_period: 1
      timeouts:
        restart: 1s
      args: []
  - name: fake-apm
    description: "Fake component apm traces generator"
    platforms: *platforms
    outputs: *outputs
    shippers: *shippers
    command: *command
```

### Agent configuration example (APM traces sender)

```yaml
inputs:
  ...
  - type: fake-apm
    id: fake-apm-traces-generator
    use_output: default
```
