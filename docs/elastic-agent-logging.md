# Elastic-Agent logging
The Elastic-Agent process defines two log outputs:
 - The "internal" core that is used by monitoring components and
   collected in the diagnostics. It's configuration is **hardcoded**.
   This output always logs to files in
   `data/elastic-agent-<hash>/logs` and uses the default configuration
   defined in `elastic-agent-libs/logp`.
 - The "default" logger that is the user-configurable logger, it logs
   to the Elastic-Agent's root folder, it can also be configured to
   log to `stderr`. When running in a container environment, it
   defaults to logging to `stderr`.

## Logger initialization
The logger initialization is **not** one of the first things done by
the Elastic-Agent. Looking at the normal Elastic-Agent run, here is
the stack trace from the logging initialization.
```
 0  0x00005e8768fea7ac in github.com/elastic/elastic-agent/pkg/core/logger.new
    at /devel/elastic-agent/pkg/core/logger/logger.go:83
 1  0x00005e8768fea54f in github.com/elastic/elastic-agent/pkg/core/logger.NewFromConfig
    at /devel/elastic-agent/pkg/core/logger/logger.go:65
 2  0x00005e876b511dba in github.com/elastic/elastic-agent/internal/pkg/agent/cmd.runElasticAgent
    at /devel/elastic-agent/internal/pkg/agent/cmd/run.go:151
 3  0x00005e876b5119e5 in github.com/elastic/elastic-agent/internal/pkg/agent/cmd.run
    at /devel/elastic-agent/internal/pkg/agent/cmd/run.go:138
 4  0x00005e876b51127e in github.com/elastic/elastic-agent/internal/pkg/agent/cmd.newRunCommandWithArgs.func1
    at /devel/elastic-agent/internal/pkg/agent/cmd/run.go:78
```
This means some log entries might not be collected by diagnostics or
shipped to the monitoring output. Everything in the `run` function
happens before the logger initialization.

https://github.com/elastic/elastic-agent/blob/574aa5db629231d56062ab40d27ccceb02cbbe4d/internal/pkg/agent/cmd/run.go#L104-L138

## Internal logging
The internal logging output is crucial for the Elastic-Agent
self-monitoring and diagnostics. It is instantiated by
[MakeInternalFileOutput](https://github.com/elastic/elastic-agent/blob/574aa5db629231d56062ab40d27ccceb02cbbe4d/pkg/core/logger/logger.go#L153-L182)
function that is called when a new logger is created. Its default
configuration is:
 - 10Mb per log file
 - Maximum of 7 log files
 - Rotated on startup
 - ECS/JSON encoded
 - UTC timestamps

There is also a second file output for events that is configured via
`agent.logging.event_data`. It shares the same log level as the main
logger and can only be configured for standalone agents. For
Fleet-Managed agents it will always use the default values:
 - 5Mb per log file
 - Maximum of 2 log files
 - Do not rotate on startup
 - ECS/JSON encoded
 - UTC timestamps

## Default logging
The default logger is the easiest to discover because it's user
configurable, logs to the Agent's root directory and can output to
`stderr`. It's default configuration comes from
https://github.com/elastic/elastic-agent/blob/574aa5db629231d56062ab40d27ccceb02cbbe4d/pkg/core/logger/logger.go#L132-L148
and defaults to:
 - 20Mb per log file
 - Maximum of 7 log files
 - Rotated on startup
 - ECS/JSON are not explicitly set

## Collecting logs for diagnostics
The Elastic-Agent will only collect
`data/elastic-agent-<hash>/logs`. The functions responsible for
collecting logs during diagnostics are:
 - [`zipLogs`](https://github.com/elastic/elastic-agent/blob/574aa5db629231d56062ab40d27ccceb02cbbe4d/internal/pkg/diagnostics/diagnostics.go#L383-L415)
 - [`zipLogsWithPath`](https://github.com/elastic/elastic-agent/blob/574aa5db629231d56062ab40d27ccceb02cbbe4d/internal/pkg/diagnostics/diagnostics.go#L418-L476)

`zipLogsWithPath` always appends the `/logs` to whatever path it
receives.

## Total footprint
Given the two log outputs and their default log rotation policies, the
Elastic-Agent needs about 210Mb (20Mb x 7 + 10Mb x 7 = 210Mb) of disk
for logging.
