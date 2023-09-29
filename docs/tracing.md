# Elastic agent APM configuration


## Configuration
The APM elastic agent configuration in `elastic-agent.yml` looks like this (the keys under `apm` have the same meaning 
and usage as a regular [APM configuration](https://www.elastic.co/guide/en/apm/agent/go/current/configuration.html)) :
  ```yaml
  agent.monitoring:
    traces: true
    apm:
      hosts:
        - <apm host url>
      environment: <apm environment>
      secret_token: <redacted>
      api_key: <redacted>
      global_labels:
        k1: v1
        k2: v2
      tls:
        skip_verify: true
        server_certificate: <path to the server certificate>
        server_ca: <path to the server CA>
  ```
APM configuration is only available in `elastic-agent.yml` configuration file (Fleet does not support these settings at the moment):
- for a standalone agent the configuration is reloaded by default from file in case of changes while the agent is running (unless the configuration reload mechanism has been disabled using `agent.reload.enabled` setting)
- for a managed agent, the configuration is read once at startup and then added to every policy change coming from Fleet: in this case changes to APM configuration require a restart of agent to be picked up

## APM config propagation

APM propagation to components requires agent APM traces to be enabled (`agent.monitoring.traces` must be set to `true`).
Elastic Agent will propagate the APM parameters defined in its configuration to all the components it manages.
APM configuration is sent to the components via the control protocol, specifically in the [APMConfig message](https://github.com/elastic/elastic-agent-client/blob/5c7929a9889af5047137fabcb8f16ea38653ab97/elastic-agent-client.proto#L188-L208).

At the moment the agent supports only Elastic APM configuration but since want to support OTLP protocol the APM configuration
has a dedicated field for Elastic, and we will put support for other protocols side-by-side (see [APMConfig message](https://github.com/elastic/elastic-agent-client/blob/5c7929a9889af5047137fabcb8f16ea38653ab97/elastic-agent-client.proto#L188-L208))

The components can consume the configuration by using the [`Unit.Expected()`](https://github.com/elastic/elastic-agent-client/blob/5c7929a9889af5047137fabcb8f16ea38653ab97/pkg/client/unit.go#L166-L177) 
from the [`UnitChanged`](https://github.com/elastic/elastic-agent-client/blob/5c7929a9889af5047137fabcb8f16ea38653ab97/pkg/client/client_v2.go#L126-L131)
object published by the elastic-agent-client. The [TriggeredAPMChange](https://github.com/elastic/elastic-agent-client/blob/5c7929a9889af5047137fabcb8f16ea38653ab97/pkg/client/client_v2.go#L63) 
trigger flag will be set whenever there is a change in APM configuration.

Components are expected to take appropriate action to reload/re-instantiate their APM instrumentation.
How that happens in detail depends on what sort of APM objects the component uses, for example:
- if the component uses a decorated http server it may be needed to stop (gracefully) the current server, recreate it with the new configuration and start the new one.
- if it uses a custom Tracer object, it will need to create the new one, close the old one and swap them safely.

The list above is obviously not an exhaustive one, the handling of APM configuration change will probably be specific
to each component/unit.