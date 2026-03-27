# Verifier Receiver

## Overview

The Verifier Receiver is a custom EDOT (Elastic Distribution of OpenTelemetry) collector component that verifies permissions for identity federation based integrations and reports results as OTEL logs to Elasticsearch.

## Features

- **Multi-Provider Architecture**: Extensible design supporting AWS, Azure, GCP, Okta, and other providers
- **Permission Registry**: Internal mapping of integration types to their required permissions
- **Active Verification**: Makes actual API calls to verify permissions (granted/denied)
- **On-demand verification**: Proactively check all permissions for attached integrations
- **Structured reporting**: Output OTEL logs with full policy/integration context to Elasticsearch
- **Policy-aware**: Results are grouped by Identity Federation, policy, and integration for clear remediation
- **Verification Methods**: Supports `api_call` (minimal API calls) and `dry_run` (EC2-style DryRun parameter)

## Supported Providers

| Provider | Status | Integrations |
|----------|--------|--------------|
| **AWS** | Active | CloudTrail, GuardDuty, Security Hub, S3, EC2, VPC Flow Logs, WAF, Route53, ELB, CloudFront, CSPM, Asset Inventory |
| **Azure** | Active | Activity Logs, Audit Logs, Blob Storage, CSPM, Asset Inventory |
| **GCP** | Active | Audit Logs, Cloud Storage, Pub/Sub, CSPM, Asset Inventory |
| **Okta** | Planned | System Logs, User Events |

## Configuration

The receiver configuration follows the RFC structure for Identity Federation Permission Verification:

```yaml
receivers:
  verifier:
    # Identity Federation identification
    identity_federation_id: "cc-12345"
    identity_federation_name: "Production Connector"
    
    # Verification session
    verification_id: "verify-abc123"
    verification_type: "on_demand"  # or "scheduled"
    
    # Provider credentials
    providers:
      # AWS Authentication - Identity Federation STS AssumeRole
      aws:
        credentials:
          role_arn: "arn:aws:iam::123456789012:role/ElasticAgentRole"
          external_id: "elastic-external-id-from-setup"
          default_region: "us-east-1"
      
      # Azure Authentication (future)
      # azure:
      #   credentials:
      #     tenant_id: "your-tenant-id"
      #     client_id: "your-client-id"
      #     client_secret: "your-client-secret"
      
      # GCP Authentication — choose one mode:
      #
      # Production (Identity Federation / WIF):
      # gcp:
      #   credentials:
      #     workload_identity_provider: "//iam.googleapis.com/projects/PROJECT_NUMBER/..."
      #     service_account_email: "sa@PROJECT_ID.iam.gserviceaccount.com"
      #
      # Testing (Application Default Credentials):
      # gcp:
      #   credentials:
      #     use_default_credentials: true  # project from GOOGLE_CLOUD_PROJECT or GCE metadata
      
      # Okta Authentication (future)
      # okta:
      #   credentials:
      #     domain: "dev-123456.okta.com"
      #     api_token: "your-api-token"
    
    # Policy context from Fleet API (no permissions specified!)
    policies:
      - policy_id: "policy-1"
        policy_name: "AWS Security Monitoring"
        integrations:
          - integration_id: "int-cloudtrail-001"
            integration_type: "aws_cloudtrail"
            integration_name: "AWS CloudTrail"
            integration_version: "2.17.0"  # Version-aware permissions
            config:
              account_id: "123456789012"
              region: "us-east-1"
          - integration_id: "int-guardduty-001"
            integration_type: "aws_guardduty"
            integration_name: "AWS GuardDuty"
            integration_version: "1.5.0"
            config:
              account_id: "123456789012"
              region: "us-east-1"
      
      - policy_id: "policy-2"
        policy_name: "AWS Infrastructure"
        integrations:
          - integration_id: "int-ec2-001"
            integration_type: "aws_ec2"
            integration_name: "AWS EC2 Metrics"
            # No integration_version - uses latest permission set
            config:
              account_id: "123456789012"
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `identity_federation_id` | `string` | Yes | - | Unique identifier for the Identity Federation |
| `identity_federation_name` | `string` | No | - | Human-readable name of the Identity Federation |
| `verification_id` | `string` | Yes | - | Unique identifier for this verification session |
| `verification_type` | `string` | No | `on_demand` | Type of verification (`on_demand` or `scheduled`) |
| `providers` | `ProvidersConfig` | No | - | Provider credentials for AWS, Azure, GCP, Okta |
| `policies` | `[]PolicyConfig` | Yes | - | List of policies to verify |

### Provider Credentials

#### AWS (`providers.aws.credentials`)

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `role_arn` | `string` | Yes* | - | ARN of the IAM role to assume |
| `external_id` | `string` | Yes* | - | External ID for confused deputy protection |
| `default_region` | `string` | No | `us-east-1` | Default AWS region for API calls |
| `use_default_credentials` | `bool` | No | `false` | Use AWS SDK default credential chain (for testing) |

*Required when using Identity Federation authentication. Not required if `use_default_credentials` is `true`.

#### Azure (`providers.azure.credentials`)

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `tenant_id` | `string` | Yes* | Azure AD tenant ID |
| `client_id` | `string` | Yes* | Azure AD application client ID |
| `client_secret` | `string` | Yes* | Azure AD application secret |
| `subscription_id` | `string` | No | Azure subscription ID |
| `use_managed_identity` | `bool` | No | Use Azure Managed Identity |

#### GCP (`providers.gcp.credentials`)

Two mutually exclusive authentication modes are supported.

**Identity Federation (production)** — requires `workload_identity_provider`. The GCP project
identifier is derived automatically: from `service_account_email` when set (extracts
`PROJECT_ID` from `name@PROJECT_ID.iam.gserviceaccount.com`), otherwise from the project
number embedded in the WIF audience (`//iam.googleapis.com/projects/PROJECT_NUMBER/...`).

**Application Default Credentials (testing only)** — requires only `use_default_credentials:
true`. The project identifier is resolved at runtime from `google.FindDefaultCredentials`:
the `GOOGLE_CLOUD_PROJECT` (or `GCLOUD_PROJECT`) environment variable, the ADC JSON file's
`quota_project_id`, or the GCE/GKE metadata server. No WIF fields are needed or used.

| Option | Type | Mode | Description |
|--------|------|------|-------------|
| `workload_identity_provider` | `string` | Identity Federation | Full WIF provider resource name; project number derived from this |
| `service_account_email` | `string` | Identity Federation | GCP service account to impersonate via WIF; project ID derived from this when set |
| `use_default_credentials` | `bool` | Testing | Use ADC (`gcloud auth application-default login`); project from `GOOGLE_CLOUD_PROJECT` env var or GCE metadata |

#### Okta (`providers.okta.credentials`) - Future

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `domain` | `string` | Yes | Okta domain (e.g., `dev-123456.okta.com`) |
| `api_token` | `string` | Yes* | Okta API token |
| `client_id` | `string` | No | OAuth 2.0 client ID |
| `private_key` | `string` | No | Private key for OAuth authentication |

### PolicyConfig

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `policy_id` | `string` | Yes | Unique identifier for the policy |
| `policy_name` | `string` | No | Human-readable name of the policy |
| `integrations` | `[]IntegrationConfig` | Yes | List of integrations within this policy |

### IntegrationConfig

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `integration_id` | `string` | No | Unique identifier for the integration instance |
| `integration_type` | `string` | Yes | Package/integration type (e.g., `aws_cloudtrail`) |
| `integration_name` | `string` | No | Human-readable name of the integration |
| `integration_version` | `string` | No | Semantic version of the integration package (e.g., `2.17.0`). Different versions may require different permissions. When empty, the latest registered permission set is used. |
| `config` | `map[string]interface{}` | No | Provider-specific configuration |

## Supported Integration Types

### AWS Integrations

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `aws_cloudtrail` | `cloudtrail:LookupEvents`, `cloudtrail:DescribeTrails`, `s3:GetObject`, `s3:ListBucket`, `sqs:ReceiveMessage` |
| `aws_guardduty` | `guardduty:ListDetectors`, `guardduty:GetFindings`, `guardduty:ListFindings` |
| `aws_securityhub` | `securityhub:GetFindings`, `securityhub:DescribeHub` |
| `aws_s3` | `s3:ListBucket`, `s3:GetObject`, `s3:GetBucketLocation` |
| `aws_ec2` | `ec2:DescribeInstances`, `ec2:DescribeRegions`, `cloudwatch:GetMetricData` |
| `aws_vpcflow` | `logs:FilterLogEvents`, `logs:DescribeLogGroups`, `ec2:DescribeFlowLogs` |
| `aws_waf` | `wafv2:GetWebACL`, `wafv2:ListWebACLs`, `s3:GetObject` |
| `aws_route53` | `logs:FilterLogEvents`, `logs:DescribeLogGroups`, `route53:ListHostedZones` |
| `aws_elb` | `s3:GetObject`, `s3:ListBucket`, `elasticloadbalancing:DescribeLoadBalancers` |
| `aws_cloudfront` | `s3:GetObject`, `s3:ListBucket`, `cloudfront:ListDistributions` |

### Azure Integrations

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `azure_activitylogs` | `Microsoft.Insights/eventtypes/values/Read` |
| `azure_auditlogs` | `Microsoft.Insights/eventtypes/values/Read` |
| `azure_blob_storage` | `Microsoft.Storage/storageAccounts/blobServices/containers/read` |

### GCP Integrations

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `gcp_audit` | `logging.logEntries.list` |
| `gcp_storage` | `storage.objects.get`, `storage.objects.list` |
| `gcp_pubsub` | `pubsub.subscriptions.consume` |

### Okta Integrations (Planned)

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `okta_system` | `okta.logs.read` |
| `okta_users` | `okta.users.read` |

## Output

The receiver emits OTEL logs following the RFC structure. Each log record represents a single permission verification result.

### Resource Attributes

| Attribute | Description |
|-----------|-------------|
| `identity_federation.id` | Identity Federation identifier |
| `identity_federation.name` | Identity Federation name |
| `verification.id` | Verification session ID |
| `verification.timestamp` | When verification started |
| `verification.type` | `on_demand` or `scheduled` |
| `service.name` | Always `permission-verifier` |
| `service.version` | Receiver version |

### Scope

| Attribute | Value |
|-----------|-------|
| `name` | `elastic.permission_verification` |
| `version` | `0.0.0` |

### Log Record Attributes

| Attribute | Description |
|-----------|-------------|
| `policy.id` | Policy identifier |
| `policy.name` | Policy name |
| `integration.id` | Integration instance identifier |
| `integration.name` | Integration name |
| `integration.type` | Integration type (e.g., `aws_cloudtrail`) |
| `integration.version` | Integration package version (e.g., `2.17.0`) or `unspecified` |
| `provider.type` | Provider type (`aws`, `azure`, `gcp`, `okta`) |
| `provider.account` | Account identifier (if available) |
| `provider.region` | Region (if available) |
| `permission.action` | Permission being checked (e.g., `cloudtrail:LookupEvents`) |
| `permission.category` | Category (`data_access`, `management`) |
| `permission.status` | Result (`granted`, `denied`, `error`, `skipped`) |
| `permission.required` | Whether this permission is required |
| `permission.error_code` | Error code from provider (if status is `denied` or `error`) |
| `permission.error_message` | Error message from provider (if status is `denied` or `error`) |
| `verification.method` | Method used (`api_call`, `dry_run`, `http_probe`) |
| `verification.endpoint` | API endpoint called for verification |
| `verification.duration_ms` | Time taken for verification in milliseconds |

## Version-Aware Permissions

The permission registry supports versioned permission sets per integration type. Different versions of an integration package may require different permissions (for example, a new version might add a required SQS permission for queue-based ingestion).

### How It Works

- Each integration type is registered with one or more semver constraints (e.g., `>=2.0.0`, `>=1.0.0,<2.0.0`)
- When `integration_version` is provided, the registry matches it against the constraints and returns the appropriate permission set
- When `integration_version` is omitted, the latest (first registered) permission set is used
- If the version does not match any constraint, a warning log with `permission.error_code: UnsupportedVersion` is emitted

### Example: AWS CloudTrail Version Differences

| Version Range | Change |
|---------------|--------|
| `>=2.0.0` | `sqs:ReceiveMessage` and `sqs:DeleteMessage` became **required** (queue-based ingestion is the default) |
| `>=1.0.0,<2.0.0` | `sqs:ReceiveMessage` and `sqs:DeleteMessage` are **optional** (direct S3 polling was the default) |

## Architecture

The receiver uses a registry-based architecture for extensibility:

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

### Adding a New Provider

1. Create a verifier in `internal/verifier/` implementing the `Verifier` interface
2. Create a factory function (e.g., `NewAzureVerifierFactory()`)
3. Register the factory in `receiver.go`
4. Add integration mappings in `registry.go`

## Authentication

Each CSP supports two authentication modes:

1. **Identity Federation** (production) - OIDC JWT-based federated credential exchange
2. **Default Credentials** (testing) - uses the platform's default credential chain

### AWS

```bash
AWS_PROFILE=your-profile ./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/test-aws.yaml
```

### GCP

```bash
gcloud auth application-default login
GCP_PROJECT_ID=your-project-id ./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/test-gcp.yaml
```

### Azure

```bash
az login
AZURE_SUBSCRIPTION_ID=your-subscription-id ./_build/elastic-collector-components --config ./receiver/verifierreceiver/testdata/test-azure.yaml
```

## Example Pipeline

```yaml
receivers:
  verifier:
    identity_federation_id: "${IDENTITY_FEDERATION_ID}"
    verification_id: "${VERIFICATION_ID}"
    
    providers:
      aws:
        credentials:
          role_arn: "${AWS_ROLE_ARN}"
          external_id: "${AWS_EXTERNAL_ID}"
          default_region: "us-east-1"
    
    policies:
      - policy_id: "policy-1"
        policy_name: "AWS Security Monitoring"
        integrations:
          - integration_id: "int-cloudtrail-001"
            integration_type: "aws_cloudtrail"
            integration_name: "AWS CloudTrail"
            integration_version: "2.17.0"
            config:
              region: "us-east-1"

exporters:
  elasticsearch:
    endpoints: ["${ES_ENDPOINT}"]
    api_key: "${ES_API_KEY}"
    logs_index: "logs-verifier_otel.verification-default"

service:
  pipelines:
    logs:
      receivers: [verifier]
      exporters: [elasticsearch]
```

## Development Status

This receiver is currently in **development** stability level.

### Planned
- [ ] Okta verifier implementation
- [ ] Fleet API integration for triggering verification

## Related

- [RFC: OTEL Permission Verifier Receiver](https://docs.google.com/document/d/...)
- [GitHub Issue #15628](https://github.com/elastic/security-team/issues/15628)
- [Integration Package](https://github.com/elastic/integrations/tree/main/packages/verifier_otel)
