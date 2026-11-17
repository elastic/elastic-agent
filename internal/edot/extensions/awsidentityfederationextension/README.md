# AWS Identity Federation Extension

Resolves AWS credentials for Elastic managed integrations. AWS-SDK-based components
consume them through their `credentials_provider` option.

This extension is intended for Elastic-managed deployments and is not meant to be
configured by hand.

## Configuration

| Parameter      | Required | Description |
| -------------- | -------- | ----------- |
| `role_arn`     | yes      | IAM role to assume. |
| `session_name` | no       | Role session name. |
| `duration`     | no       | Requested session duration. |
| `sts_region`   | no       | Region of the STS endpoint. |

## Example

```yaml
extensions:
  awsidentityfederation:
    role_arn: arn:aws:iam::123456789012:role/example

receivers:
  awscloudwatch:
    credentials_provider: awsidentityfederation

service:
  extensions: [awsidentityfederation]
```
