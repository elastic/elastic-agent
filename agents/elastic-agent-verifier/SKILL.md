---
name: elastic-agent-verifier
description: Verify and validate elastic-agent standalone mode by running the verifier receiver to check cloud permissions for AWS, Azure, and GCP integrations (CSPM, Asset Discovery, CloudTrail, etc.). Use when the user asks to verify agent permissions, validate cloud integrations, run permission checks, test standalone agent policies, or check CSPM/Asset Discovery access.
---

# Elastic Agent Standalone Verifier

Verify cloud integration permissions by running the verifier receiver with a verifier policy against real cloud APIs. Supports two run modes: `elastic-agent otel` (full agent build) or `elastic-otel-collector` directly (quick development build). Both make the same API calls against AWS, Azure, and GCP to confirm the required permissions for each integration.

## Step 1: Discover, Detect, and Ask

This step runs automatically when the skill is triggered. Do all three sub-steps before asking the user anything.

### 1a. Discover available integrations from the codebase

Read the registry source to find all currently registered integrations:

```
Read: internal/edot/receivers/verifierreceiver/registry.go
```

Parse all `r.register("<integration_type>", ...)` calls. Extract:
- The integration type key (e.g. `aws_cspm`, `azure_asset_inventory`)
- The provider (part before the underscore: `aws`, `azure`, `gcp`)
- The template name (part after the underscore: `cspm`, `asset_inventory`)

Group discovered integrations by provider. This is the source of truth for what options to present.

### 1b. Detect existing credentials

Run these checks in parallel to see what's already configured:

```bash
aws sts get-caller-identity 2>&1
az account show 2>&1
gcloud auth application-default print-access-token 2>&1 | head -1
```

For each provider, determine:
- **Authenticated**: command succeeded (show the identity/account found)
- **Not authenticated**: command failed (will need user action)

Also check for existing env vars:
```bash
echo "AWS_PROFILE=${AWS_PROFILE:-unset} AWS_REGION=${AWS_REGION:-unset}"
echo "AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID:-unset}"
echo "GCP_PROJECT_ID=${GCP_PROJECT_ID:-unset}"
```

### 1c. Present discovered options to the user

Present what was discovered. Build the options dynamically from step 1a.

**Question 1 - Cloud Provider** (allow_multiple: true):
- Prompt: "Which cloud providers do you want to verify? [detected status shown]"
- Options: build from discovered providers, annotating each with auth status:
  - e.g. "AWS (authenticated as arn:aws:iam::123456789012:user/dev)"
  - e.g. "Azure (not authenticated - will need `az login`)"
  - e.g. "GCP (authenticated, project: my-project)"

**Question 2 - Integrations** (allow_multiple: true):
- Prompt: "Which integrations should be verified?"
- Options: build from discovered integrations for the selected providers, plus "All available"
  - e.g. for AWS: "CSPM (aws_cspm)", "Asset Discovery (aws_asset_inventory)", "CloudTrail (aws_cloudtrail)", etc.
  - Only show integrations for providers the user selected

If any selected provider is **not authenticated**, prompt:
- **AWS**: "Enter your AWS profile name, or set AWS_ACCESS_KEY_ID env var"
- **Azure**: "Run `az login` first, then enter your subscription ID"
- **GCP**: "Run `gcloud auth application-default login` first, then enter your project ID"

For **AWS region**, if `AWS_REGION` is not set, ask which region to use (default: us-east-1).

**Question 3 - Run mode**:
- Prompt: "How do you want to run the verifier?"
- Options:
  - "elastic-agent otel (full agent build via mage build:all)"
  - "elastic-otel-collector directly (quick build from internal/edot)"

### 1d. Generate the policy

Using the user's selections, generate a verifier policy YAML. Start from the example templates in `examples/` and:
1. Include only the selected providers in the `providers` block (all with `use_default_credentials: true`)
2. Include only the selected integrations in the `policies` block
3. Substitute detected/provided values for region, subscription_id, project_id
4. **Always** include a `service.telemetry.metrics` block that overrides the default Prometheus port (8888 is commonly already in use):
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
   The older `service.telemetry.metrics.address` format is **rejected** by collector v0.145.0+. Always use the `readers` format above.
5. Write the generated policy to a temp file for execution

## Architecture

The verifier can be executed two ways:

- **`elastic-agent otel`** -- runs the EDOT (Elastic Distribution of OTel) collector as a subprocess. The agent execs the `elastic-otel-collector` binary from its components directory, passing through all flags including `--config`. Requires a full `mage build:all`.
- **`elastic-otel-collector` directly** -- runs the EDOT binary standalone, skipping the agent wrapper. Faster to build (`go build` from `internal/edot`), useful during development.

Both execute identical verifier receiver code and produce the same output.

The verifier receiver is an OTel Collector component at:

```
internal/edot/receivers/verifierreceiver/
  config.go       # Config structs (providers, policies, integrations)
  receiver.go     # Verification execution, OTEL log emission
  registry.go     # PermissionRegistry: integration type -> required permissions
  internal/verifier/
    verifier.go       # Types: Result, Status, Permission, ProviderConfig
    aws_verifier.go   # AWS SDK API calls
    azure_verifier.go # Azure SDK API calls
    gcp_verifier.go   # GCP SDK API calls
```

The registry maps integration types (e.g. `aws_cspm`, `azure_asset_inventory`) to required permissions. Each permission is verified via `api_call` or `dry_run` against the real cloud APIs.

## Step 2: Build and Run

Based on the user's run mode choice from step 1c:

### Option A: elastic-agent otel

Build the full elastic-agent:

```bash
cd <repo-root>
mage build:all
```

This produces `build/elastic-agent`. However, `mage build:all` does **not** place the `elastic-otel-collector` component in the directory that `elastic-agent otel` expects. Run the agent once to discover the expected path from the error:

```bash
./build/elastic-agent otel --config /tmp/<generated-policy>.yaml 2>&1
```

The error will show the exact path, e.g.:
```
failed to exec .../build/data/elastic-agent-<hash>/components/elastic-otel-collector: no such file or directory
```

Build the EDOT binary and place it at that path:

```bash
mkdir -p build/data/elastic-agent-<hash>/components
cd internal/edot
go build -ldflags="-s -w -extldflags '-Wl,-ld_classic'" -o ../../build/data/elastic-agent-<hash>/components/elastic-otel-collector .
```

(Replace `<hash>` with the value from the error message.)

Then run again:

```bash
./build/elastic-agent otel --config /tmp/<generated-policy>.yaml
```

### Option B: elastic-otel-collector directly

Build just the EDOT binary from the `internal/edot` module. On **macOS ARM64**, the classic linker flag is required to work around an Xcode 15 bug (`B/BL out of range` on binaries >128MB TEXT):

```bash
cd internal/edot
go build -ldflags="-s -w -extldflags '-Wl,-ld_classic'" -o build/elastic-otel-collector .
```

On Linux or macOS x86_64 you can omit `-extldflags`:

```bash
go build -ldflags="-s -w" -o build/elastic-otel-collector .
```

Run:

```bash
./internal/edot/build/elastic-otel-collector --config /tmp/<generated-policy>.yaml
```

### Set environment variables

Export any values the user provided in step 1c:

```bash
export AWS_PROFILE=<if-provided>
export AZURE_SUBSCRIPTION_ID=<if-provided>
export GCP_PROJECT_ID=<if-provided>
```

Skip any that were already detected as configured.

### Notes

Both options run the same verifier receiver code. Capture the full stdout/stderr output for parsing. The verifier runs once and the collector stays running after emitting results -- kill the process after capturing output.

## Step 3: Verify Events and Report Results

After running the verifier:

1. **Check for successful emission**: look for `"Permission verification logs emitted"` in the output with `log_count > 0`.

2. **Parse the debug exporter output**: each permission check appears as an OTEL log record with body:
   ```
   Permission check: <provider>/<action> - <status>
   ```
   Where `<status>` is one of: `granted`, `denied`, `error`, `skipped`.

3. **Present a permission report** to the user as a markdown table:

   ```
   ## Permission Verification Report

   **Connector:** <cloud_connector_id> | **Verification:** <verification_id>

   | Provider | Integration | Permission | Required | Status | Error | Duration |
   |----------|-------------|------------|----------|--------|-------|----------|
   | aws | cspm | iam:GetAccountSummary | Yes | granted | | 245ms |
   | aws | cspm | ec2:DescribeInstances | Yes | denied | AccessDenied | 189ms |
   ...

   **Summary:** X checked, Y granted, Z denied, W errors, V skipped
   ```

4. **Diagnose failures**: for `denied` or `error` results, check:
   - Auth: are default credentials configured? (`AWS_PROFILE`, `az login`, `gcloud auth`)
   - Permissions: does the IAM role/user have the required policy attached?
   - Region: is the correct region/subscription/project set?
   - Error codes: `VerifierNotInitialized` means provider credentials missing from config; `AccessDenied`/`UnauthorizedAccess` means the IAM entity lacks the permission.

## Verifier Policy Structure

Policies are OTel Collector configs with the `verifier` receiver:

```yaml
receivers:
  verifier:
    cloud_connector_id: "local-test"          # Required: identifier
    verification_id: "verify-001"             # Required: unique session ID
    cloud_connector_name: "Test"              # Optional: display name
    namespace: "default"                      # Optional: data stream namespace
    account_type: "single_account"            # Optional: single_account|organization
    verification_type: "on_demand"            # Optional: on_demand|scheduled

    providers:
      aws:
        credentials:
          use_default_credentials: true       # Use AWS_PROFILE or env vars
          default_region: "us-east-1"
      azure:
        credentials:
          use_default_credentials: true       # Use az login
          subscription_id: "${AZURE_SUBSCRIPTION_ID}"
      gcp:
        credentials:
          use_default_credentials: true       # Use gcloud ADC
          project_id: "${GCP_PROJECT_ID}"

    policies:
      - policy_id: "policy-1"
        policy_name: "Security Policy"
        integrations:
          - policy_template: "cspm"           # Maps to registry key: aws_cspm
            package_name: "aws"
            package_policy_id: "pp-001"
            package_title: "AWS"
            package_version: "1.0.0"          # Optional: version-aware lookup

exporters:
  debug:
    verbosity: detailed                       # Shows full OTEL log records

service:
  telemetry:
    metrics:
      readers:
        - pull:
            exporter:
              prometheus:
                host: localhost
                port: 18888                   # Avoids conflict with default 8888
  pipelines:
    logs:
      receivers: [verifier]
      exporters: [debug]
```

The registry lookup key is `<package_name>_<policy_template>` (e.g. `aws_cspm`, `gcp_asset_inventory`).

## Supported Integrations

| Provider | Integration Type | Category | Key Permissions |
|----------|-----------------|----------|-----------------|
| AWS | `aws_cspm` | security_posture | iam:GetAccountSummary, ec2:DescribeInstances, s3:GetBucketAcl, cloudtrail:DescribeTrails, config:DescribeComplianceByConfigRule |
| AWS | `aws_asset_inventory` | asset_inventory | ec2:DescribeInstances, ec2:DescribeSecurityGroups, s3:ListAllMyBuckets, iam:ListUsers, rds:DescribeDBInstances |
| AWS | `aws_cloudtrail` | data_access | cloudtrail:LookupEvents, s3:GetObject, sqs:ReceiveMessage (v2.0.0+ requires sqs:DeleteMessage) |
| AWS | `aws_guardduty` | data_access | guardduty:ListDetectors, guardduty:GetFindings |
| AWS | `aws_securityhub` | data_access | securityhub:GetFindings, securityhub:DescribeHub |
| AWS | `aws_s3` | data_access | s3:ListBucket, s3:GetObject |
| AWS | `aws_ec2` | data_access | ec2:DescribeInstances, cloudwatch:GetMetricData |
| AWS | `aws_vpcflow` | data_access | logs:FilterLogEvents, logs:DescribeLogGroups |
| AWS | `aws_waf` | management | wafv2:GetWebACL, wafv2:ListWebACLs, s3:GetObject |
| AWS | `aws_route53` | data_access | logs:FilterLogEvents, route53:ListHostedZones |
| AWS | `aws_elb` | data_access | s3:GetObject, elasticloadbalancing:DescribeLoadBalancers |
| AWS | `aws_cloudfront` | data_access | s3:GetObject, cloudfront:ListDistributions |
| Azure | `azure_cspm` | security_posture | subscriptions/read, virtualMachines/read, storageAccounts/read, sites/config/Read |
| Azure | `azure_asset_inventory` | asset_inventory | subscriptions/resources/read, virtualMachines/read, networkSecurityGroups/read, storageAccounts/read |
| Azure | `azure_activitylogs` | data_access | eventtypes/values/Read |
| Azure | `azure_auditlogs` | data_access | eventtypes/values/Read |
| Azure | `azure_blob_storage` | data_access | blobServices/containers/read |
| GCP | `gcp_cspm` | security_posture | cloudasset.assets.searchAllResources, resourcemanager.projects.get, compute.instances.list, storage.buckets.list |
| GCP | `gcp_asset_inventory` | asset_inventory | cloudasset.assets.searchAllResources, resourcemanager.projects.get, compute.instances.list |
| GCP | `gcp_audit` | data_access | logging.logEntries.list |
| GCP | `gcp_storage` | data_access | storage.objects.get, storage.objects.list |
| GCP | `gcp_pubsub` | data_access | pubsub.subscriptions.consume |

For full permission details with required/optional flags and verification methods, see [reference.md](reference.md).

## Self-Learning Workflow

The discovery step (1a) always reads `registry.go` from the codebase, so the skill automatically picks up new integrations as they're added. The Supported Integrations table above is a static snapshot for quick reference, but the registry is the source of truth.

When adapting discovered integrations to policy YAML, use:
```yaml
- policy_template: "<template>"    # Part after the underscore in the registry key
  package_name: "<package>"        # Part before the underscore
```
For example, registry key `aws_cspm` becomes `policy_template: "cspm"`, `package_name: "aws"`.

If verification fails, iterate: check credentials, adjust regions/subscriptions/projects, and re-run.

## Additional Resources

- For full permission registry, config reference, output format, and troubleshooting, see [reference.md](reference.md)
- Example policies: [examples/](examples/)
