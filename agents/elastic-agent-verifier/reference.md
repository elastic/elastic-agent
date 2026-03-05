# Verifier Receiver Reference

## Permission Registry

Source: `internal/edot/receivers/verifierreceiver/registry.go`

### AWS Integrations

#### aws_cloudtrail (v2.0.0+)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| cloudtrail:LookupEvents | Yes | api_call | data_access |
| cloudtrail:DescribeTrails | Yes | api_call | management |
| cloudtrail:GetTrailStatus | No | api_call | management |
| s3:GetObject | Yes | api_call | data_access |
| s3:ListBucket | Yes | api_call | data_access |
| sqs:ReceiveMessage | Yes | api_call | data_access |
| sqs:DeleteMessage | Yes | api_call | data_access |

#### aws_cloudtrail (v1.x: >=1.0.0,<2.0.0)

Same as v2.0.0+ except `sqs:ReceiveMessage` and `sqs:DeleteMessage` are **optional** (Required=No).

#### aws_guardduty (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| guardduty:ListDetectors | Yes | api_call | management |
| guardduty:GetFindings | Yes | api_call | data_access |
| guardduty:ListFindings | Yes | api_call | data_access |

#### aws_securityhub (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| securityhub:GetFindings | Yes | api_call | data_access |
| securityhub:BatchGetSecurityControls | No | api_call | data_access |
| securityhub:DescribeHub | Yes | api_call | management |

#### aws_s3 (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| s3:ListBucket | Yes | api_call | data_access |
| s3:GetObject | Yes | api_call | data_access |
| s3:GetBucketLocation | No | api_call | management |

#### aws_ec2 (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| ec2:DescribeInstances | Yes | dry_run | data_access |
| ec2:DescribeRegions | Yes | api_call | management |
| cloudwatch:GetMetricData | Yes | api_call | data_access |

#### aws_vpcflow (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| logs:FilterLogEvents | Yes | api_call | data_access |
| logs:DescribeLogGroups | Yes | api_call | management |
| logs:DescribeLogStreams | Yes | api_call | management |
| ec2:DescribeFlowLogs | No | api_call | management |

#### aws_waf (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| wafv2:GetWebACL | Yes | api_call | management |
| wafv2:ListWebACLs | Yes | api_call | management |
| s3:GetObject | Yes | api_call | data_access |
| s3:ListBucket | Yes | api_call | data_access |

#### aws_route53 (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| logs:FilterLogEvents | Yes | api_call | data_access |
| logs:DescribeLogGroups | Yes | api_call | management |
| route53:ListHostedZones | No | api_call | management |

#### aws_elb (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| s3:GetObject | Yes | api_call | data_access |
| s3:ListBucket | Yes | api_call | data_access |
| elasticloadbalancing:DescribeLoadBalancers | No | api_call | management |

#### aws_cloudfront (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| s3:GetObject | Yes | api_call | data_access |
| s3:ListBucket | Yes | api_call | data_access |
| cloudfront:ListDistributions | No | api_call | management |

#### aws_cspm (>=0.0.0)

Requires the SecurityAudit managed policy.

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| iam:GetAccountSummary | Yes | api_call | security_posture |
| ec2:DescribeInstances | Yes | dry_run | security_posture |
| s3:GetBucketAcl | Yes | api_call | security_posture |
| cloudtrail:DescribeTrails | Yes | api_call | security_posture |
| config:DescribeComplianceByConfigRule | Yes | api_call | security_posture |

#### aws_asset_inventory (>=0.0.0)

Requires the SecurityAudit managed policy.

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| ec2:DescribeInstances | Yes | dry_run | asset_inventory |
| ec2:DescribeSecurityGroups | Yes | api_call | asset_inventory |
| s3:ListAllMyBuckets | Yes | api_call | asset_inventory |
| iam:ListUsers | Yes | api_call | asset_inventory |
| rds:DescribeDBInstances | Yes | api_call | asset_inventory |

### Azure Integrations

#### azure_activitylogs (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| Microsoft.Insights/eventtypes/values/Read | Yes | api_call | data_access |

#### azure_auditlogs (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| Microsoft.Insights/eventtypes/values/Read | Yes | api_call | data_access |

#### azure_blob_storage (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| Microsoft.Storage/storageAccounts/blobServices/containers/read | Yes | api_call | data_access |

#### azure_cspm (>=0.0.0)

Requires Reader built-in role + custom role with Microsoft.Web permissions.

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| Microsoft.Resources/subscriptions/read | Yes | api_call | security_posture |
| Microsoft.Compute/virtualMachines/read | Yes | api_call | security_posture |
| Microsoft.Storage/storageAccounts/read | Yes | api_call | security_posture |
| Microsoft.Web/sites/config/Read | Yes | api_call | security_posture |

#### azure_asset_inventory (>=0.0.0)

Requires Reader built-in role.

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| Microsoft.Resources/subscriptions/resources/read | Yes | api_call | asset_inventory |
| Microsoft.Compute/virtualMachines/read | Yes | api_call | asset_inventory |
| Microsoft.Network/networkSecurityGroups/read | Yes | api_call | asset_inventory |
| Microsoft.Storage/storageAccounts/read | Yes | api_call | asset_inventory |

### GCP Integrations

#### gcp_audit (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| logging.logEntries.list | Yes | api_call | data_access |

#### gcp_storage (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| storage.objects.get | Yes | api_call | data_access |
| storage.objects.list | Yes | api_call | data_access |

#### gcp_pubsub (>=0.0.0)

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| pubsub.subscriptions.consume | Yes | api_call | data_access |

#### gcp_cspm (>=0.0.0)

Requires roles/cloudasset.viewer and roles/browser.

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| cloudasset.assets.searchAllResources | Yes | api_call | security_posture |
| resourcemanager.projects.get | Yes | api_call | security_posture |
| compute.instances.list | Yes | api_call | security_posture |
| storage.buckets.list | Yes | api_call | security_posture |

#### gcp_asset_inventory (>=0.0.0)

Requires roles/cloudasset.viewer and roles/browser.

| Permission | Required | Method | Category |
|------------|----------|--------|----------|
| cloudasset.assets.searchAllResources | Yes | api_call | asset_inventory |
| resourcemanager.projects.get | Yes | api_call | asset_inventory |
| compute.instances.list | Yes | api_call | asset_inventory |

## Config Field Reference

Source: `internal/edot/receivers/verifierreceiver/config.go`

### Top-Level Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cloud_connector_id` | string | Yes | Identifier for the Cloud Connector being verified |
| `cloud_connector_name` | string | No | Human-readable name |
| `namespace` | string | No | Kibana Space / data stream namespace (default: "default") |
| `account_type` | string | No | "single_account" or "organization" |
| `verification_id` | string | Yes | Unique ID for this verification session |
| `verification_type` | string | No | "on_demand" (default) or "scheduled" |
| `providers` | object | Yes | Provider credentials (see below) |
| `policies` | array | Yes | List of policies with integrations |

### Provider Credentials (Default Credentials Mode)

**AWS** (`providers.aws.credentials`):

| Field | Type | Description |
|-------|------|-------------|
| `use_default_credentials` | bool | Use AWS_PROFILE or env vars (AWS_ACCESS_KEY_ID, etc.) |
| `default_region` | string | Default region for API calls (e.g. "us-east-1") |

**Azure** (`providers.azure.credentials`):

| Field | Type | Description |
|-------|------|-------------|
| `use_default_credentials` | bool | Use DefaultAzureCredential (az login, env vars, managed identity) |
| `subscription_id` | string | Azure subscription ID for resource queries |

**GCP** (`providers.gcp.credentials`):

| Field | Type | Description |
|-------|------|-------------|
| `use_default_credentials` | bool | Use Application Default Credentials (gcloud auth) |
| `project_id` | string | GCP project ID for resource queries |

### Policy Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy_id` | string | Yes | Unique policy identifier |
| `policy_name` | string | No | Human-readable name |
| `integrations` | array | Yes | List of integrations to verify |

### Integration Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy_template` | string | Yes | Template name (e.g. "cspm", "cloudtrail") |
| `package_name` | string | Yes | Package name (e.g. "aws", "azure", "gcp") |
| `package_policy_id` | string | No | Package policy instance ID |
| `package_title` | string | No | Display title (e.g. "AWS") |
| `package_version` | string | No | Semver version for version-aware permission lookup |
| `config` | map | No | Provider-specific config (region, account_id, project_id, etc.) |

Registry lookup key: `<package_name>_<policy_template>` (e.g. `aws_cspm`).

## Verification Methods

| Method | Description | Used By |
|--------|-------------|---------|
| `api_call` | Calls the real API and checks for access errors | Most permissions |
| `dry_run` | Uses AWS DryRun parameter (validates without executing) | ec2:DescribeInstances |
| `http_probe` | Makes an HTTP request to an endpoint | Reserved for future use |
| `graphql_query` | Executes a GraphQL query | Reserved for future use |

## OTEL Log Output Format

Source: `internal/edot/receivers/verifierreceiver/receiver.go` (`emitPermissionCheckLog`)

Each permission check produces one OTEL log record with:

**Body:** `Permission check: <provider>/<action> - <status>`

**Severity mapping:**
- INFO: granted, skipped
- WARN: denied (optional permission)
- ERROR: denied (required permission), error

**Resource attributes** (shared across all log records):

| Attribute | Example |
|-----------|---------|
| `cloud_connector.id` | "cc-test-12345" |
| `cloud_connector.name` | "Local Test Connector" |
| `cloud_connector.namespace` | "default" |
| `data_stream.type` | "logs" |
| `data_stream.dataset` | "cloud_connector.permission_verification" |
| `data_stream.namespace` | "default" |
| `verification.id` | "verify-local-001" |
| `verification.timestamp` | "2026-03-04T10:30:00Z" |
| `verification.type` | "on_demand" |
| `service.name` | "permission-verifier" |
| `service.version` | "1.0.0" |

**Log attributes** (per permission check):

| Attribute | Description |
|-----------|-------------|
| `policy.id` | Policy identifier |
| `policy.name` | Policy display name |
| `policy_template` | Integration template (e.g. "cspm") |
| `package.name` | Package name (e.g. "aws") |
| `package.title` | Package display title |
| `package.version` | Package version or "unspecified" |
| `package_policy.id` | Package policy instance ID |
| `provider.type` | "aws", "azure", or "gcp" |
| `account_type` | "single_account" or "organization" |
| `permission.action` | The permission being checked |
| `permission.category` | "data_access", "management", "security_posture", "asset_inventory" |
| `permission.status` | "granted", "denied", "error", "skipped" |
| `permission.required` | true/false |
| `permission.error_code` | Error code (e.g. "AccessDenied", "VerifierNotInitialized") |
| `permission.error_message` | Error description |
| `verification.method` | "api_call", "dry_run" |
| `verification.endpoint` | API endpoint called |
| `verification.duration_ms` | Duration in milliseconds |
| `verification.verified_at` | ISO 8601 timestamp |

## Troubleshooting

| Error Code | Cause | Fix |
|------------|-------|-----|
| `VerifierNotInitialized` | Provider credentials not configured in the policy YAML | Add `use_default_credentials: true` under the provider's credentials |
| `AccessDenied` (AWS) | IAM role/user lacks the required permission | Attach SecurityAudit managed policy or add specific permissions |
| `UnauthorizedAccess` (Azure) | Service principal/user lacks the required role | Assign Reader role at subscription scope |
| `AuthorizationError` (GCP) | Service account lacks the required IAM permission | Grant cloudasset.viewer and browser roles |
| `InvalidClientTokenId` (AWS) | AWS credentials are invalid or expired | Refresh credentials: `aws sso login` or re-export env vars |
| `ExpiredToken` (AWS) | Session token has expired | Refresh session: `aws sts get-session-token` |
| `AADSTS700024` (Azure) | Azure AD token expired | Re-authenticate: `az login` |
| `AADSTS700082` (Azure) | Refresh token expired due to inactivity | Re-authenticate: `az login --scope https://management.core.windows.net//.default` |
| `UnsupportedIntegration` | Integration type not in the registry | Check `registry.go` for supported types; the integration may be new |
| `UnsupportedVersion` | Package version doesn't match any registered constraint | Check version constraints in `registry.go`; use a supported version |

### Common Issues

**All permissions show "error" with VerifierNotInitialized:**
The provider block is missing or `use_default_credentials` is not set. Ensure the providers section includes the correct CSP with `use_default_credentials: true`.

**Process exits immediately with no output:**
Check that `cloud_connector_id` and `verification_id` are set (both are required). Also verify at least one policy with at least one integration is configured.

**Some permissions granted, others denied:**
The IAM entity has partial permissions. Check which specific permissions are denied and add them to the IAM policy. For CSPM, the AWS SecurityAudit managed policy covers all required permissions.

**macOS ARM64 build fails with "B/BL out of range":**
The binary TEXT section exceeds the 128MB ARM64 branch range limit. Use `-extldflags '-Wl,-ld_classic'` to invoke the classic Apple linker which handles branch islands correctly.

**Startup fails with "bind: address already in use" on port 8888:**
The OTel collector's default Prometheus metrics endpoint (`localhost:8888`) is occupied by another process. Add a `service.telemetry.metrics` block to the policy YAML to use a different port:
```yaml
service:
  telemetry:
    metrics:
      readers:
        - pull:
            exporter:
              prometheus:
                host: localhost
                port: 18888
```

**Startup fails with "'migration.MetricsConfigV030' has invalid keys: address":**
The policy uses the old telemetry format (`service.telemetry.metrics.address`). Collector v0.145.0+ requires the `readers` format shown above. Do **not** use `address: localhost:18888`.

**`elastic-agent otel` fails with "no such file or directory" for elastic-otel-collector:**
`mage build:all` builds the `elastic-agent` binary but does not place the `elastic-otel-collector` component in the expected `build/data/elastic-agent-<hash>/components/` directory. Read the exact path from the error message, create the directory, and build the EDOT binary into it:
```bash
mkdir -p build/data/elastic-agent-<hash>/components
cd internal/edot
go build -ldflags="-s -w -extldflags '-Wl,-ld_classic'" \
  -o ../../build/data/elastic-agent-<hash>/components/elastic-otel-collector .
```
Replace `<hash>` with the value shown in the error (e.g. `6b1b58`).

## Version-Aware Permissions

The registry supports semver constraints for version-specific permission sets. When `package_version` is specified in the integration config, the registry finds the first matching constraint. When omitted, the latest (first registered) set is used.

Example: `aws_cloudtrail` has two constraint sets:
- `>=2.0.0`: sqs:DeleteMessage is **required** (queue-based ingestion default)
- `>=1.0.0,<2.0.0`: sqs:DeleteMessage is **optional**

To check which constraints exist for an integration, read `registry.go` and look for multiple `r.register()` calls with the same integration type key.
