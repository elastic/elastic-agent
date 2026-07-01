# Quark Receiver

**Status: Development (mock)**

The quark receiver is a minimal mock OTel receiver that emits one log entry per
configured interval. It serves as a scaffold and test harness while real receiver
logic is developed.

## Configuration

| Field      | Type     | Default  | Description                                             |
|------------|----------|----------|---------------------------------------------------------|
| `interval` | duration | `1s`     | How often to emit a log record                          |
| `message`  | string   | `"quark"` | Text set as the body of each emitted log record        |

## Example

```yaml
receivers:
  quark:
    interval: 1s
    message: "hello from quark"

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    logs:
      receivers: [quark]
      exporters: [debug]
```

Run it:

```bash
./elastic-agent otel --config otel-config.yaml
```

## Output

Each tick produces one `plog.Logs` with a single log record:

| Field             | Value                                                        |
|-------------------|--------------------------------------------------------------|
| SeverityNumber    | `Info` (9)                                                   |
| SeverityText      | `INFO`                                                       |
| Body              | The configured `message`                                     |
| Scope name        | `github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver` |
| Scope version     | Agent build version                                          |

## Testing

See [testdata/TESTING.md](testdata/TESTING.md) for unit, integration, and
end-to-end testing instructions.
