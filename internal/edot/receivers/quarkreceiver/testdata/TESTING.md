# Testing the Quark Receiver

The quark receiver is a development-stage mock that emits one log entry per
configured interval. It requires no external credentials or services.

## 1. Unit Tests

```bash
cd internal/edot
go test ./receivers/quarkreceiver/... -v
```

## 2. Validate the OTel Config

Build `elastic-agent` binary and run

```bash
./build/<platform>/elastic-agent otel validate \
  --config internal/edot/receivers/quarkreceiver/testdata/otel-config.yaml
```

No output means the config is valid.

## 4. Run End-to-End (Stdout)

```bash
./build/<platform>/elastic-agent otel \
  --config internal/edot/receivers/quarkreceiver/testdata/otel-config.yaml
```

Expected output (one entry per second):

```
2025-01-01T00:00:00.000Z info  LogsExporter  {"resource logs": 1, "log records": 1}
Body: Str("hello from quark")
SeverityText: INFO
SeverityNumber: Info(9)
```
