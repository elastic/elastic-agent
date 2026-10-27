# AWS Identity Federation Extension

| Status        |           |
| ------------- |-----------|
| Stability     | [development]: extension   |
| Distributions | Elastic Agent (EDOT Collector) |

This extension resolves AWS credentials for the **Identity Federation** flow of Elastic
managed integrations (agentless). It fetches a short-lived JWT from the Elastic
[workload-identity-issuer](https://github.com/elastic/workload-identity-issuer) over
mTLS and exchanges it for AWS credentials with `sts:AssumeRoleWithWebIdentity` against
the customer's IAM role, which trusts the issuer's OIDC provider. AWS-SDK-based
components consume the resolved credentials through their `credentials_provider`
option, the same contract the `awscredentialsprovider` extension implements.

The token exchange is the shared libbeat implementation
(`x-pack/libbeat/common/identityfederation`), so the OTel receivers and the Beats AWS
inputs run the same workload-identity flow: per-audience token caching with refresh
before expiry, bounded retries on issuer errors, and the client certificate re-read on
every fetch so certificate rotation needs no restart.

## How it works

```
client cert (mTLS) ──▶ workload-identity-issuer ──▶ JWT (aud=sts.amazonaws.com, sub=deployment:<id>|project:<id>)
                                                        │
                                                        ▼
                                   sts:AssumeRoleWithWebIdentity(role_arn) ──▶ cached session credentials
```

Nothing is fetched at start. The first credential retrieval performs the exchange, so a
misconfigured role surfaces on the consuming component rather than blocking the
collector's startup. There is no ExternalId and no intermediate Elastic role: the
customer's trust policy binds the role to one deployment or project through the JWT
`sub` claim.

## Configuration

| Parameter      | Type     | Required | Description |
| -------------- | -------- | -------- | ----------- |
| `role_arn`     | string   | yes      | Customer IAM role assumed with `sts:AssumeRoleWithWebIdentity`. |
| `session_name` | string   | no       | Role session name passed to STS. |
| `duration`     | duration | no       | Requested session duration. STS applies its default (1h) when unset and rejects values below 15m. |
| `sts_region`   | string   | no       | Region of the STS endpoint used for the exchange. Falls back to the SDK's default region resolution (for example `AWS_REGION`), then to `us-east-1`. |
| `issuer_url`   | string   | no       | Base URL of the workload-identity-issuer, without the `/token` path. Env fallback: `WORKLOAD_IDENTITY_ISSUER_URL`. |
| `cert_file`    | string   | no       | PEM client certificate presented to the issuer. Env fallback: `WORKLOAD_IDENTITY_SSL_CERT_FILE`. |
| `key_file`     | string   | no       | PEM private key of `cert_file`. Env fallback: `WORKLOAD_IDENTITY_SSL_KEY_FILE`. |

The agentless controller injects `WORKLOAD_IDENTITY_ISSUER_URL`,
`WORKLOAD_IDENTITY_SSL_CERT_FILE` and `WORKLOAD_IDENTITY_SSL_KEY_FILE` into the pod of
every deployment on the workload-identity flow and mounts the per-tenant client
certificate, so an integration only renders the role to assume. Explicit configuration
takes precedence over the environment. `WORKLOAD_IDENTITY_SSL_CA_FILE` is honoured by
the shared token source for development issuers that are not publicly trusted.

### Example

```yaml
extensions:
  awsidentityfederation:
    role_arn: arn:aws:iam::123456789012:role/ElasticWorkloadIdentity-0d6f3b2c
    sts_region: us-east-1

receivers:
  awscloudwatch:
    region: us-east-1
    credentials_provider: awsidentityfederation
    ...

service:
  extensions: [awsidentityfederation]
```

## Consuming the extension from a component

Components resolve the extension from the host at start and type-assert it to the
`Provider` interface, or to a structurally identical local interface:

```go
ext, ok := host.GetExtensions()[cfg.CredentialsProvider]
if !ok {
    return fmt.Errorf("unknown credentials_provider extension %q", cfg.CredentialsProvider)
}
provider, ok := ext.(interface {
    GetCredentialsProvider() aws.CredentialsProvider
})
if !ok {
    return fmt.Errorf("extension %q does not provide AWS credentials", cfg.CredentialsProvider)
}
awsCfg.Credentials = provider.GetCredentialsProvider()
```

[development]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#development
