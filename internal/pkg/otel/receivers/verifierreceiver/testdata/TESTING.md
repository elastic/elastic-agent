# Testing the Verifier Receiver

The verifier receiver supports permission verification for multiple cloud and identity providers:
- **AWS** - CloudTrail, GuardDuty, S3, EC2, etc.
- **Azure** - Activity Logs, Audit Logs, Blob Storage (future implementation)
- **GCP** - Audit Logs, Cloud Storage, Pub/Sub (future implementation)
- **Okta** - System Logs, User Events (future implementation)

## 1. Unit Tests

```bash
cd receiver/verifierreceiver
go test ./... -v
```

## 2. Build the OTEL Distribution

Build the elastic-components distribution that includes the verifier receiver:

```bash
cd opentelemetry-collector-components

# Install the builder if needed
go install go.opentelemetry.io/collector/cmd/builder@latest

# Build the collector (uses Makefile)
make genelasticcol
```

This creates `./_build/elastic-collector-components`.

## 3. Run Standalone Test (No Credentials)

Quick smoke test without provider credentials - will show "VerifierNotInitialized" errors:

```bash
./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/otel-config.yaml
```

Expected output includes:
```
info    Starting verifier receiver    {"cloud_connector_id": "cc-test-minimal", ...}
debug   AWS credentials not configured
debug   Azure credentials not configured
debug   GCP credentials not configured
debug   Okta credentials not configured
warn    No verifiers initialized - permission verification will be limited
...
LogsExporter {"logs": {"resourceLogs":[{...}]}}
```

## 4. Run Standalone Test with AWS Cloud Connector Auth

Edit `testdata/test-standalone.yaml` and uncomment/set your AWS credentials:

```yaml
providers:
  aws:
    credentials:
      role_arn: "arn:aws:iam::YOUR_ACCOUNT:role/YOUR_ROLE"
      external_id: "your-external-id"
      default_region: "us-east-1"
```

Then run:

```bash
./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/test-standalone.yaml
```

Expected output with valid credentials:
```
info    Starting verifier receiver    {"cloud_connector_id": "cc-test-12345", ...}
info    Initializing AWS verifier with Cloud Connector authentication
info    AWS verifier initialized successfully
info    Verifiers initialized    {"providers": ["aws"]}
...
Permission check: aws/cloudtrail:DescribeTrails - granted
Permission check: aws/cloudtrail:GetEventSelectors - granted
...
```

## 5. Test with AWS Default Credentials

For local testing with an AWS profile, use the test-aws.yaml config:

```bash
AWS_PROFILE=your-profile ./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/test-aws.yaml
```

This verifies CloudTrail, CSPM, and Asset Inventory permissions using the default AWS credential chain.

## 6. Test with GCP Default Credentials

For local testing with GCP Application Default Credentials:

```bash
# Authenticate first
gcloud auth application-default login

# Run the test (replace with your project ID)
GCP_PROJECT_ID=your-project-id ./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/test-gcp.yaml
```

This verifies Audit Logs, CSPM, Asset Inventory, Storage, and Pub/Sub permissions.

## 7. Test with Azure Default Credentials

For local testing with Azure CLI credentials:

```bash
# Authenticate first
az login

# Run the test (replace with your subscription ID)
AZURE_SUBSCRIPTION_ID=your-subscription-id ./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/test-azure.yaml
```

This verifies Activity Logs, CSPM, Asset Inventory, and Blob Storage permissions.

## 8. Multi-Provider Configuration

Configure multiple providers in a single receiver:

```yaml
receivers:
  verifier:
    cloud_connector_id: "cc-multi-provider"
    verification_id: "verify-multi-001"
    
    providers:
      aws:
        credentials:
          use_default_credentials: true
          default_region: "us-east-1"
      
      azure:
        credentials:
          use_default_credentials: true
          subscription_id: "${AZURE_SUBSCRIPTION_ID}"
      
      gcp:
        credentials:
          use_default_credentials: true
          project_id: "${GCP_PROJECT_ID}"
    
    policies:
      - policy_id: "multi-cloud-policy"
        policy_name: "Multi-Cloud Monitoring"
        integrations:
          - policy_template: "cloudtrail"
            package_name: "aws"
            package_title: "AWS"
            package_version: "2.17.0"
          - policy_template: "activitylogs"
            package_name: "azure"
            package_title: "Azure"
          - policy_template: "audit"
            package_name: "gcp"
            package_title: "GCP"
```

## 9. Test with Elastic Agent

### Build elastic-agent with the new receiver:

```bash
cd elastic-agent

# Update go.mod to point to local opentelemetry-collector-components
go mod edit -replace github.com/elastic/elastic-agent/internal/pkg/otel/receivers/verifierreceiver=../opentelemetry-collector-components/receiver/verifierreceiver

go mod tidy
mage build
```

### Create a test OTEL config for the agent:

```yaml
# otel.yml
receivers:
  verifier:
    cloud_connector_id: "cc-agent-test"
    verification_id: "verify-agent-001"
    
    providers:
      aws:
        credentials:
          role_arn: "arn:aws:iam::123456789012:role/ElasticAgentRole"
          external_id: "your-external-id"
          default_region: "us-east-1"
    
    policies:
      - policy_id: "agent-test-policy"
        policy_name: "Agent Test Policy"
        integrations:
          - policy_template: "cloudtrail"
            package_name: "aws"
            package_title: "AWS"

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    logs:
      receivers: [verifier]
      exporters: [debug]
```

### Run the agent in OTEL mode:

```bash
./elastic-agent otel --config otel.yml
```

## 10. Test the Fleet Integration Package

### Validate the integration package:

```bash
cd integrations
elastic-package build --packages verifier_otel
elastic-package lint --packages verifier_otel
```

### Test the template rendering:

```bash
elastic-package test policy --packages verifier_otel
```

### Run system tests (requires running stack):

```bash
elastic-package stack up -d
elastic-package test system --packages verifier_otel
```

## 11. End-to-End Test with Elasticsearch

Create a config that exports to Elasticsearch:

```yaml
receivers:
  verifier:
    cloud_connector_id: "cc-e2e-test"
    verification_id: "verify-e2e-001"
    
    providers:
      aws:
        credentials:
          role_arn: "arn:aws:iam::123456789012:role/ElasticAgentRole"
          external_id: "your-external-id"
          default_region: "us-east-1"
    
    policies:
      - policy_id: "e2e-test-policy"
        policy_name: "E2E Test Policy"
        integrations:
          - policy_template: "cloudtrail"
            package_name: "aws"
            package_title: "AWS"

processors:
  batch:

exporters:
  elasticsearch:
    endpoints: ["http://localhost:9200"]
    logs_index: "logs-cloud_connector.permission_verification-default"
    mapping:
      mode: ecs

service:
  pipelines:
    logs:
      receivers: [verifier]
      processors: [batch]
      exporters: [elasticsearch]
```

Then query Elasticsearch:

```bash
curl -X GET "localhost:9200/logs-cloud_connector.permission_verification-default/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "policy_template": "cloudtrail"
    }
  }
}'
```

## 12. Version-Aware Permission Testing

The permission registry supports versioned permission sets. Different integration versions may require different permissions.

### Test with a specific version:

```yaml
policies:
  - policy_id: "version-test"
    policy_name: "Version Test"
    integrations:
      - policy_template: "cloudtrail"
        package_name: "aws"
        package_version: "2.17.0"  # v2+ requires SQS permissions
      - policy_template: "cloudtrail"
        package_name: "aws"
        package_version: "1.5.0"   # v1.x has SQS as optional
```

### Expected behavior:
- `aws_cloudtrail` v2.17.0: `sqs:ReceiveMessage` and `sqs:DeleteMessage` are **required**
- `aws_cloudtrail` v1.5.0: `sqs:ReceiveMessage` and `sqs:DeleteMessage` are **optional**
- No version specified: uses the latest (v2+) permission set
- Invalid version string: falls back to the latest permission set
- Version that matches no constraint: emits a warning with `permission.error_code: UnsupportedVersion`

### Unit tests for versioning:

```bash
go test ./... -run TestPermissionRegistry -v
```

This runs all version-aware test cases including:
- `cloudtrail_v2_-_SQS_permissions_required`
- `cloudtrail_v1_-_SQS_permissions_optional`
- `cloudtrail_no_version_-_defaults_to_latest`
- `cloudtrail_invalid_version_-_falls_back_to_latest`
- `version_constraints_are_returned`

## 13. Quick Smoke Test

For a quick verification that everything compiles:

```bash
# In opentelemetry-collector-components
cd receiver/verifierreceiver
go build ./...
go test ./... -short

# Build the full distribution
cd ../..
make genelasticcol
```

## Architecture Overview

The verifier receiver uses a **registry pattern** for extensibility:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Verifier Receiver                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────────┐     ┌───────────────────────────────┐   │
│  │ Permission        │     │ Verifier Registry             │   │
│  │ Registry          │     │                               │   │
│  │                   │     │  ┌─────────────────────────┐  │   │
│  │ aws_cloudtrail    │     │  │ AWS Verifier            │  │   │
│  │ aws_guardduty     │     │  └─────────────────────────┘  │   │
│  │ azure_activitylogs│     │  ┌─────────────────────────┐  │   │
│  │ gcp_audit         │     │  │ Azure Verifier          │  │   │
│  │ okta_system       │     │  └─────────────────────────┘  │   │
│  │ ...               │     │  ┌─────────────────────────┐  │   │
│  └───────────────────┘     │  │ GCP Verifier            │  │   │
│                            │  └─────────────────────────┘  │   │
│                            │  ┌─────────────────────────┐  │   │
│                            │  │ Okta Verifier (future)  │  │   │
│                            │  └─────────────────────────┘  │   │
│                            └───────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

To add a new provider verifier:

1. Create a new verifier in `internal/verifier/` (e.g., `azure_verifier.go`)
2. Implement the `Verifier` interface
3. Create a factory function: `NewAzureVerifierFactory()`
4. Register the factory in `newVerifierReceiver()` in `receiver.go`
5. Add integration mappings in `registry.go`
