---
navigation_title: Verifier receiver
description: The Verifier receiver is an OpenTelemetry Collector component that verifies permissions for integrations and reports results as OTEL logs.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector:
products:
  - id: elastic-agent
  - id: observability
  - id: edot-collector
---

# Verifier receiver

The Verifier receiver is an OpenTelemetry Collector component that verifies permissions for integrations (such as AWS CloudTrail, GuardDuty, S3 and others) and reports verification results as OTEL logs. It is used with Cloud Connectors to confirm that the configured IAM roles and credentials have the permissions required by each integration.

:::{important}
This receiver is in **development** stability. AWS is supported; Azure, GCP, and Okta are planned.
:::

## Get started

To use the Verifier receiver, include it in the receiver definitions of the [Collector configuration](/reference/edot-collector/config/index.md) and wire it into a logs pipeline:

```yaml
receivers:
  verifier:
    cloud_connector_id: "cc-12345"
    cloud_connector_name: "Production Connector"
    verification_id: "verify-abc123"
    verification_type: "on_demand"
    providers:
      aws:
        credentials:
          use_default_credentials: true
          default_region: "us-east-1"
    policies:
      - policy_id: "policy-1"
        policy_name: "AWS Security Monitoring"
        integrations:
          - integration_id: "int-cloudtrail-001"
            integration_type: "aws_cloudtrail"
            integration_name: "AWS CloudTrail"
            config:
              account_id: "123456789012"
              region: "us-east-1"

service:
  pipelines:
    logs:
      receivers: [verifier]
      exporters: [elasticsearch]
```

## Configuration

The receiver uses a Cloud Connector–oriented configuration: you specify the connector identity, a verification session, provider credentials, and a list of policies with their integrations. The receiver looks up required permissions per integration type and performs the checks.

### Required fields

| Option | Type | Description |
|--------|------|-------------|
| `cloud_connector_id` | `string` | Unique identifier for the Cloud Connector. |
| `verification_id` | `string` | Unique identifier for this verification session. |
| `policies` | `[]PolicyConfig` | List of policies; each policy must have at least one integration with `integration_type` set. |

### Optional fields

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cloud_connector_name` | `string` | - | Human-readable name of the Cloud Connector. |
| `verification_type` | `string` | `on_demand` | `on_demand` or `scheduled`. |
| `providers` | `ProvidersConfig` | - | Credentials for AWS, and (when available) Azure, GCP, Okta. |

### AWS credentials (`providers.aws.credentials`)

For production use with a Cloud Connector, use STS AssumeRole:

```yaml
receivers:
  verifier:
    cloud_connector_id: "${CLOUD_CONNECTOR_ID}"
    verification_id: "${VERIFICATION_ID}"
    providers:
      aws:
        credentials:
          role_arn: "arn:aws:iam::123456789012:role/ElasticAgentRole"
          external_id: "elastic-external-id-from-setup"
          default_region: "us-east-1"
    policies: []
```

For local testing, you can use the default credential chain:

```yaml
providers:
  aws:
    credentials:
      use_default_credentials: true
      default_region: "us-east-1"
```

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `role_arn` | `string` | Yes* | IAM role ARN to assume. |
| `external_id` | `string` | Yes* | External ID for assume-role. |
| `default_region` | `string` | No | Default AWS region (e.g. `us-east-1`). |
| `use_default_credentials` | `bool` | No | Use default credential chain (for testing). |

*Required when not using `use_default_credentials`.

### Policy and integration structure

Each policy must have `policy_id` and at least one integration. Each integration must specify `integration_type` (e.g. `aws_cloudtrail`, `aws_guardduty`, `aws_s3`). Optional `integration_id`, `integration_name`, and `config` provide context and provider-specific settings.

```yaml
policies:
  - policy_id: "policy-1"
    policy_name: "AWS Security Monitoring"
    integrations:
      - integration_id: "int-cloudtrail-001"
        integration_type: "aws_cloudtrail"
        integration_name: "AWS CloudTrail"
        config:
          account_id: "123456789012"
          region: "us-east-1"
      - integration_id: "int-guardduty-001"
        integration_type: "aws_guardduty"
        integration_name: "AWS GuardDuty"
        config:
          account_id: "123456789012"
          region: "us-east-1"
```

## Supported integration types (AWS)

| Integration type | Permissions verified |
|------------------|----------------------|
| `aws_cloudtrail` | CloudTrail, S3, SQS (e.g. `LookupEvents`, `GetObject`, `ReceiveMessage`) |
| `aws_guardduty` | GuardDuty (e.g. `ListDetectors`, `GetFindings`, `ListFindings`) |
| `aws_securityhub` | Security Hub (e.g. `GetFindings`, `DescribeHub`) |
| `aws_s3` | S3 (e.g. `ListBucket`, `GetObject`, `GetBucketLocation`) |
| `aws_ec2` | EC2 and CloudWatch (e.g. `DescribeInstances`, `DescribeRegions`, `GetMetricData`) |
| `aws_vpcflow` | VPC Flow Logs (e.g. `FilterLogEvents`, `DescribeLogGroups`, `DescribeFlowLogs`) |
| `aws_waf` | WAFv2 and S3 |
| `aws_route53` | Route53 and CloudWatch Logs |
| `aws_elb` | ELB and S3 |
| `aws_cloudfront` | CloudFront and S3 |

Azure, GCP, and Okta integration types are planned.

## Output

The receiver emits OTEL logs. Each log record represents a permission verification result. Resource and log attributes include:

- **Resource**: `cloud_connector.id`, `cloud_connector.name`, `verification.id`, `verification.type`, `service.name` (`permission-verifier`)
- **Log attributes**: `policy.id`, `policy.name`, `integration.id`, `integration.type`, `provider.type`, `permission.action`, `permission.status` (`granted` / `denied` / `error` / `skipped`), `permission.error_code`, `permission.error_message`, `verification.method`, `verification.duration_ms`

Export these logs to {{es}} (for example with the Elasticsearch exporter) and use the `logs-cloud_connector.permission_verification-*` data stream or a custom index for dashboards and alerts.

## Example pipeline

```yaml
receivers:
  verifier:
    cloud_connector_id: "${CLOUD_CONNECTOR_ID}"
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
            config:
              region: "us-east-1"

exporters:
  elasticsearch:
    endpoints: ["${ES_ENDPOINT}"]
    api_key: "${ES_API_KEY}"
    logs_index: "logs-cloud_connector.permission_verification-default"

service:
  pipelines:
    logs:
      receivers: [verifier]
      exporters: [elasticsearch]
```

## Resources

* [Verifier receiver source](https://github.com/elastic/opentelemetry-collector-components/tree/main/receiver/verifierreceiver)
* [Configure logs collection in EDOT](../config/configure-logs-collection.md)
