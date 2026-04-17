# PII Handling in Elastic Agent

## Overview

Here is a plain-language overview of where PII can show up, how we limit exposure, and what risks still exist.

---

## 1. Where PII Can Show Up

### 1.1 Config Files

**What’s sensitive:**
- Authentication credentials (usernames, passwords, API keys)
- OAuth tokens and bearer tokens
- TLS certificates and passphrases
- SSL private keys
- Database connection strings with embedded credentials
- API keys and secret keys
- HTTP authorization headers

**Files to watch:**
- `elastic-agent.yml` - Main agent configuration
- `elastic-agent.fleet.yml` - Fleet-managed configuration
- Integration configurations in `.fleet-config` directory
- Input-specific config files

Note: We do not rewrite config files to redact PII.

**Kubernetes secrets:**
When running on Kubernetes, secret values are typically provided via env vars using Kubernetes `secretKeyRef`. This is a Kubernetes feature (not an agent-specific one), but it is the recommended way to keep secrets out of static config.

Examples in this repo:
- [deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed/fleet-enrollment-token-patch.yaml](deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed/fleet-enrollment-token-patch.yaml)
- [deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone/api-key-patch.yaml](deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone/api-key-patch.yaml)

### 1.2 Application and Event Data

Upstream data often contains PII by nature (audit logs, app logs, API request/response data, cloud audit events). Elastic Agent will collect and forward it unless you filter or redact it downstream.

### 1.3 Diagnostic Bundles

**What’s included (collected by the Diagnostic Bundle Collector):**
- Agent configuration (includes credentials if not redacted)
- Agent logs (may include PII if logged)
- State information from running inputs
- Integration configuration details

---

## 2. How We Reduce Exposure

### 2.1 Automatic Redaction in Diagnostics

Diagnostic bundles redact common sensitive fields based on name patterns. This is handled by the Diagnostic Bundle Collector with built‑in Redactors, which apply redaction before bundle output is generated.

Redaction logic lives in: [internal/pkg/diagnostics/diagnostics.go](internal/pkg/diagnostics/diagnostics.go)

**In short:**
- Looks for common sensitive names (auth, password, token, key, secret, certificate, etc.)
- Replaces matching values with a redaction marker
- Includes a few exceptions for known false positives

### 2.2 Input‑Level Redaction Configuration

You can explicitly mark fields to redact in DEBUG logs for some inputs. This is for troubleshooting without leaking sensitive fields. When enabled, Redactors apply those rules to log output. This is not a generic, agent‑wide setting and availability depends on the input.

**You can:**
- List specific fields to redact (e.g., password, token, api_key)
- Target nested fields (e.g., auth.credentials.token)
- Choose masking vs deletion

**What to expect:**
- Only affects DEBUG logs
- Doesn’t change the actual data flow
- Lets you be as granular as you need

**Example (redact in DEBUG logs):**
    redact:
      fields:
        - auth.token
        - headers.Authorization
        - user.email
      delete: false