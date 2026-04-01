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

      # Azure Authentication
      # azure:
      #   credentials:
      #     tenant_id: "your-tenant-id"
      #     client_id: "your-client-id"

      # GCP Authentication — choose one mode:
      #
      # Production (Identity Federation / WIF):
      # gcp:
      #   credentials:
      #     audience: "//iam.googleapis.com/projects/PROJECT_NUMBER/..."
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
          - policy_template: "cloudtrail"
            package_name: "aws"
            package_policy_id: "pp-cloudtrail-001"
            package_title: "AWS"
            package_version: "2.17.0"  # Version-aware permissions
            config:
              account_id: "123456789012"
              region: "us-east-1"
          - policy_template: "guardduty"
            package_name: "aws"
            package_policy_id: "pp-guardduty-001"
            package_title: "AWS"
            package_version: "1.5.0"
            config:
              account_id: "123456789012"
              region: "us-east-1"

      - policy_id: "policy-2"
        policy_name: "AWS Infrastructure"
        integrations:
          - policy_template: "ec2"
            package_name: "aws"
            package_title: "AWS"
            # No package_version - uses latest permission set
            config:
              account_id: "123456789012"

processors:
  # Data stream routing and identity federation namespace are configured at the
  # pipeline level via a resource processor. The namespace value comes from the
  # Fleet policy (Kibana Space) and is substituted by Fleet when the policy is applied.
  resource/verifier:
    attributes:
      - action: insert
        key: data_stream.type
        value: logs
      - action: insert
        key: data_stream.dataset
        value: verifier_otel.verification
      - action: insert
        key: data_stream.namespace
        value: "default"  # replaced by ${var:namespace} in Fleet-managed deployments
      - action: insert
        key: identity_federation.namespace
        value: "default"  # replaced by ${var:namespace} in Fleet-managed deployments

service:
  pipelines:
    logs/verifier:
      receivers: [verifier]
      processors: [resource/verifier]
      exporters: [...]
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `identity_federation_id` | `string` | Yes | - | Unique identifier for the Identity Federation |
| `identity_federation_name` | `string` | No | - | Human-readable name of the Identity Federation |
| `account_type` | `string` | No | - | Account scope: `single-account` or `organization-account` |
| `verification_id` | `string` | Yes | - | Unique identifier for this verification session |
| `verification_type` | `string` | No | `on_demand` | Type of verification (`on_demand` or `scheduled`) |
| `providers` | `ProvidersConfig` | No | - | Provider credentials for AWS, Azure, GCP, Okta |
| `policies` | `[]PolicyConfig` | Yes | - | List of policies to verify |

> **Namespace and data stream routing** are not receiver config fields. They are configured at the OTel pipeline level via a `resource/verifier` processor (see example above). When deployed via Fleet, the namespace is substituted from the Kibana Space (`${var:namespace}`), matching the pattern used by all other EDOT integrations.

### Provider Credentials

#### AWS (`providers.aws.credentials`)

Two mutually exclusive authentication modes are supported.

**Identity Federation (production)**: JWT → `WebIdentityRoleProvider(GlobalRoleARN)` →
`AssumeRole(RoleARN, ExternalID)`. The AWS account is implicit in `role_arn`.

**Default credentials (testing)**: Uses the standard AWS SDK credential chain in order:
environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`),
`~/.aws/credentials` profile (optionally selected via `AWS_PROFILE`), container credential
provider (ECS), and EC2/EKS instance metadata service (IMDSv2).

| Option | Type | Mode | Description |
|--------|------|------|-------------|
| `role_arn` | `string` | Identity Federation | ARN of the IAM role to assume in the customer account |
| `external_id` | `string` | Identity Federation | External ID for confused deputy protection |
| `use_default_credentials` | `bool` | Testing | Use AWS SDK default credential chain |

#### Azure (`providers.azure.credentials`)

Two mutually exclusive authentication modes are supported.

**Identity Federation (production)**: JWT → `ClientAssertionCredential(TenantID, ClientID)` →
Azure access token. The Azure subscription is discovered automatically at runtime by listing
the subscriptions visible to the authenticated principal — no subscription ID is needed in config.

**Default credentials (testing)**: `DefaultAzureCredential` chains the following sources in
order: environment variables (`AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID`),
workload identity, managed identity, Azure CLI (`az login`), and Azure Developer CLI (`azd`).
The subscription is also discovered automatically at runtime.

| Option | Type | Mode | Description |
|--------|------|------|-------------|
| `tenant_id` | `string` | Identity Federation | Azure AD tenant ID |
| `client_id` | `string` | Identity Federation | Azure AD application client ID |
| `use_default_credentials` | `bool` | Testing | Use `DefaultAzureCredential` (`az login` / env vars / managed identity) |

#### GCP (`providers.gcp.credentials`)

Two mutually exclusive authentication modes are supported.

**Identity Federation (production)** — requires `audience`. The GCP project
identifier is derived automatically: from `service_account_email` when set (extracts
`PROJECT_ID` from `name@PROJECT_ID.iam.gserviceaccount.com`), otherwise from the project
number embedded in the audience (`//iam.googleapis.com/projects/PROJECT_NUMBER/...`).

**Application Default Credentials (testing only)** — requires only `use_default_credentials:
true`. The project identifier is resolved at runtime from `google.FindDefaultCredentials`:
the `GOOGLE_CLOUD_PROJECT` (or `GCLOUD_PROJECT`) environment variable, the ADC JSON file's
`quota_project_id`, or the GCE/GKE metadata server. No WIF fields are needed or used.

| Option | Type | Mode | Description |
|--------|------|------|-------------|
| `audience` | `string` | Identity Federation | Full WIF provider resource name used as the STS exchange audience; project number derived from this |
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
| `policy_template` | `string` | Yes | Policy template name from the integration package (e.g., `cloudtrail`, `activitylogs`). Combined with `package_name` to form the registry lookup key. |
| `package_name` | `string` | Yes | Integration package name (e.g., `aws`, `azure`, `gcp`, `okta`) |
| `package_policy_id` | `string` | No | Unique identifier for the package policy instance |
| `package_title` | `string` | No | Human-readable title of the integration package (e.g., `AWS`) |
| `package_version` | `string` | No | Semantic version of the integration package (e.g., `2.17.0`). Different versions may require different permissions. When empty, the latest registered permission set is used. |
| `config` | `map[string]interface{}` | No | Provider-specific configuration (e.g., `region`, `account_id`, `project_id`) |

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

The receiver sets identity federation and verification attributes. Data stream routing attributes (`data_stream.*`) and `identity_federation.namespace` are set by the `resource/verifier` pipeline processor so that the namespace flows from the Fleet policy (Kibana Space), not from the receiver config.

**Set by the receiver:**

| Attribute | Description |
|-----------|-------------|
| `identity_federation.id` | Identity Federation identifier |
| `identity_federation.name` | Identity Federation name (when configured) |
| `verification.id` | Verification session ID |
| `verification.timestamp` | When verification started (RFC 3339) |
| `verification.type` | `on_demand` or `scheduled` |
| `service.name` | Always `permission-verifier` |
| `service.version` | Receiver version |

**Set by the `resource/verifier` processor:**

| Attribute | Description |
|-----------|-------------|
| `identity_federation.namespace` | Kibana Space the Identity Federation belongs to |
| `data_stream.type` | Always `logs` |
| `data_stream.dataset` | Always `verifier_otel.verification` |
| `data_stream.namespace` | Kibana Space namespace; routes data to `logs-verifier_otel.verification-{namespace}` |

### Scope

| Attribute | Value |
|-----------|-------|
| `name` | `elastic.permission_verification` |
| `version` | `1.0.0` |

### Log Record Attributes

| Attribute | Description |
|-----------|-------------|
| `policy.id` | Policy identifier |
| `policy.name` | Policy name |
| `policy_template` | Policy template name from the integration package (e.g., `cloudtrail`) |
| `package.name` | Integration package name (e.g., `aws`) |
| `package.title` | Human-readable integration title |
| `package.version` | Integration package version (e.g., `2.17.0`) or `unspecified` |
| `package_policy.id` | Package policy instance identifier |
| `account_type` | Account scope (`single-account` or `organization-account`) |
| `provider.type` | Provider type (`aws`, `azure`, `gcp`, `okta`) |
| `provider.account` | Account identifier (if available) |
| `provider.region` | Region (if available) |
| `provider.project_id` | GCP project identifier (if available) |
| `permission.action` | Permission being checked (e.g., `cloudtrail:LookupEvents`) |
| `permission.category` | Category (`data_access`, `management`) |
| `permission.status` | Result (`granted`, `denied`, `error`, `skipped`) |
| `permission.required` | Whether this permission is required |
| `permission.error_code` | Error code from provider (if status is `denied` or `error`) |
| `permission.error_message` | Error message from provider (if status is `denied` or `error`) |
| `verification.method` | Method used (`api_call`, `dry_run`, `http_probe`) |
| `verification.endpoint` | API endpoint called for verification |
| `verification.duration_ms` | Time taken for verification in milliseconds |
| `verification.verified_at` | Timestamp of the individual permission check (RFC 3339) |

## Version-Aware Permissions

The permission registry supports versioned permission sets per integration type. Different versions of an integration package may require different permissions (for example, a new version might add a required SQS permission for queue-based ingestion).

### How It Works

- Each integration type is registered with one or more semver constraints (e.g., `>=2.0.0`, `>=1.0.0,<2.0.0`)
- When `package_version` is provided, the registry matches it against the constraints and returns the appropriate permission set
- When `package_version` is omitted, the latest (first registered) permission set is used
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

    policies:
      - policy_id: "policy-1"
        policy_name: "AWS Security Monitoring"
        integrations:
          - policy_template: "cloudtrail"
            package_name: "aws"
            package_title: "AWS"
            package_version: "2.17.0"
            config:
              region: "us-east-1"

processors:
  # Namespace flows from the Fleet policy (Kibana Space) to data stream routing.
  # In Fleet-managed deployments, ${var:namespace} is substituted automatically.
  resource/verifier:
    attributes:
      - action: insert
        key: data_stream.type
        value: logs
      - action: insert
        key: data_stream.dataset
        value: verifier_otel.verification
      - action: insert
        key: data_stream.namespace
        value: "${NAMESPACE}"
      - action: insert
        key: identity_federation.namespace
        value: "${NAMESPACE}"

exporters:
  elasticsearch/otel:
    endpoints: ["${ES_ENDPOINT}"]
    api_key: "${ES_API_KEY}"
    mapping:
      mode: otel

service:
  pipelines:
    logs/verifier:
      receivers: [verifier]
      processors: [resource/verifier]
      exporters: [elasticsearch/otel]
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
