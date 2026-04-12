// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver

import (
	"context"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/metadata"
	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"
)

func TestReceiver_StartShutdown(t *testing.T) {
	config := &Config{
		IdentityFederationID:   "cc-12345",
		IdentityFederationName: "Test Connector",
		VerificationID:         "verify-test-001",
		VerificationType:       "on_demand",
		Providers: ProvidersConfig{
			AWS: AWSProviderConfig{
				Credentials: AWSCredentials{
					RoleARN:    "arn:aws:iam::123456789012:role/ElasticAgentRole",
					ExternalID: "elastic-test-external-id",
				},
			},
		},
		Policies: []PolicyConfig{
			{
				PolicyID:   "policy-1",
				PolicyName: "AWS Security Monitoring",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate:  "cloudtrail",
						PackageName:     "aws",
						PackagePolicyID: "pp-cloudtrail-001",
						PackageTitle:    "AWS",
						Config: map[string]interface{}{
							"account_id": "123456789012",
							"region":     "us-east-1",
						},
					},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	receiver := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()

	err := receiver.Start(ctx, nil)
	require.NoError(t, err)

	// Wait for verification to complete
	<-receiver.done

	err = receiver.Shutdown(ctx)
	require.NoError(t, err)

	// Verify logs were emitted
	logs := consumer.AllLogs()
	require.NotEmpty(t, logs, "expected logs to be emitted")

	// Check the first log batch
	firstLog := logs[0]
	require.Equal(t, 1, firstLog.ResourceLogs().Len())

	resourceLog := firstLog.ResourceLogs().At(0)

	// Verify resource attributes per RFC specification
	attrs := resourceLog.Resource().Attributes()
	serviceName, ok := attrs.Get("service.name")
	require.True(t, ok)
	assert.Equal(t, "permission-verifier", serviceName.Str())

	federationID, ok := attrs.Get("identity_federation.id")
	require.True(t, ok)
	assert.Equal(t, "cc-12345", federationID.Str())

	verificationID, ok := attrs.Get("verification.id")
	require.True(t, ok)
	assert.Equal(t, "verify-test-001", verificationID.Str())

	// Verify log records
	scopeLogs := resourceLog.ScopeLogs()
	require.Equal(t, 1, scopeLogs.Len())

	// Check scope name per RFC
	assert.Equal(t, "elastic.permission_verification", scopeLogs.At(0).Scope().Name())

	logRecords := scopeLogs.At(0).LogRecords()
	assert.GreaterOrEqual(t, logRecords.Len(), 1, "expected log records for permissions")

	// Verify first log record attributes
	record := logRecords.At(0)

	// Policy context
	policyID, ok := record.Attributes().Get("policy.id")
	require.True(t, ok)
	assert.Equal(t, "policy-1", policyID.Str())

	// Integration context (Fleet package metadata)
	policyTemplate, ok := record.Attributes().Get("policy_template")
	require.True(t, ok)
	assert.Equal(t, "cloudtrail", policyTemplate.Str())

	packageName, ok := record.Attributes().Get("package.name")
	require.True(t, ok)
	assert.Equal(t, "aws", packageName.Str())

	// Provider context
	providerType, ok := record.Attributes().Get("provider.type")
	require.True(t, ok)
	assert.Equal(t, "aws", providerType.Str())

	// Permission status
	status, ok := record.Attributes().Get("permission.status")
	require.True(t, ok)
	assert.Contains(t, []string{"pending", "granted", "denied", "error", "skipped"}, status.Str())
}

func TestReceiver_WithoutAWSCredentials(t *testing.T) {
	config := &Config{
		IdentityFederationID: "cc-12345",
		VerificationID:       "verify-test-002",
		// No provider credentials configured
		Policies: []PolicyConfig{
			{
				PolicyID: "policy-1",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate: "cloudtrail",
						PackageName:    "aws",
						PackageTitle:   "AWS",
					},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	receiver := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()

	err := receiver.Start(ctx, nil)
	require.NoError(t, err)

	<-receiver.done

	err = receiver.Shutdown(ctx)
	require.NoError(t, err)

	// Should still emit logs but with error status
	logs := consumer.AllLogs()
	require.NotEmpty(t, logs)

	logRecords := logs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.GreaterOrEqual(t, logRecords.Len(), 1)

	// First record should have error status since no credentials
	record := logRecords.At(0)
	status, ok := record.Attributes().Get("permission.status")
	require.True(t, ok)
	assert.Equal(t, "error", status.Str())

	errorCode, ok := record.Attributes().Get("permission.error_code")
	require.True(t, ok)
	assert.Equal(t, "VerifierNotInitialized", errorCode.Str())
}

func TestReceiver_UnsupportedIntegration(t *testing.T) {
	config := &Config{
		IdentityFederationID: "cc-12345",
		VerificationID:       "verify-test-003",
		Policies: []PolicyConfig{
			{
				PolicyID: "policy-1",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate: "unknown",
						PackageName:    "unknown",
						PackageTitle:   "Unknown Integration",
					},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	receiver := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()

	err := receiver.Start(ctx, nil)
	require.NoError(t, err)

	<-receiver.done

	err = receiver.Shutdown(ctx)
	require.NoError(t, err)

	logs := consumer.AllLogs()
	require.NotEmpty(t, logs)

	logRecords := logs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, logRecords.Len())

	record := logRecords.At(0)
	assert.Equal(t, "WARN", record.SeverityText())
	assert.Contains(t, record.Body().Str(), "Unsupported integration type")

	status, ok := record.Attributes().Get("permission.status")
	require.True(t, ok)
	assert.Equal(t, "skipped", status.Str())
}

func TestReceiver_MultipleIntegrations(t *testing.T) {
	config := &Config{
		IdentityFederationID: "cc-12345",
		VerificationID:       "verify-test-004",
		Providers: ProvidersConfig{
			AWS: AWSProviderConfig{
				Credentials: AWSCredentials{
					RoleARN:    "arn:aws:iam::123456789012:role/ElasticAgentRole",
					ExternalID: "elastic-test-external-id",
				},
			},
		},
		Policies: []PolicyConfig{
			{
				PolicyID:   "policy-1",
				PolicyName: "AWS Security",
				Integrations: []IntegrationConfig{
					{PolicyTemplate: "cloudtrail", PackageName: "aws"},
					{PolicyTemplate: "guardduty", PackageName: "aws"},
				},
			},
			{
				PolicyID:   "policy-2",
				PolicyName: "AWS Storage",
				Integrations: []IntegrationConfig{
					{PolicyTemplate: "s3", PackageName: "aws"},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	receiver := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()

	err := receiver.Start(ctx, nil)
	require.NoError(t, err)

	<-receiver.done

	err = receiver.Shutdown(ctx)
	require.NoError(t, err)

	logs := consumer.AllLogs()
	require.NotEmpty(t, logs)

	logRecords := logs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.GreaterOrEqual(t, logRecords.Len(), 10, "expected log records for all integration permissions")

	// Collect unique policy IDs and policy templates
	policyIDs := make(map[string]bool)
	policyTemplates := make(map[string]bool)

	for i := 0; i < logRecords.Len(); i++ {
		record := logRecords.At(i)
		if policyID, ok := record.Attributes().Get("policy.id"); ok {
			policyIDs[policyID.Str()] = true
		}
		if tmpl, ok := record.Attributes().Get("policy_template"); ok {
			policyTemplates[tmpl.Str()] = true
		}
	}

	assert.True(t, policyIDs["policy-1"])
	assert.True(t, policyIDs["policy-2"])
	assert.True(t, policyTemplates["cloudtrail"])
	assert.True(t, policyTemplates["guardduty"])
	assert.True(t, policyTemplates["s3"])
}

func TestReceiver_AzureIntegrations(t *testing.T) {
	config := &Config{
		IdentityFederationID:   "cc-azure-001",
		IdentityFederationName: "Azure Connector",
		AccountType:            "single-account",
		VerificationID:         "verify-azure-001",
		VerificationType:       "on_demand",
		Providers: ProvidersConfig{
			Azure: AzureProviderConfig{
				Credentials: AzureCredentials{
					TenantID: "00000000-0000-0000-0000-000000000000",
					ClientID: "11111111-1111-1111-1111-111111111111",
				},
			},
		},
		Policies: []PolicyConfig{
			{
				PolicyID:   "policy-azure-1",
				PolicyName: "Azure Activity Monitoring",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate:  "activitylogs",
						PackageName:     "azure",
						PackagePolicyID: "pp-activitylogs-001",
						PackageTitle:    "Azure",
						PackageVersion:  "1.5.0",
					},
					{
						PolicyTemplate: "auditlogs",
						PackageName:    "azure",
						PackageTitle:   "Azure",
					},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	rcvr := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()
	err := rcvr.Start(ctx, nil)
	require.NoError(t, err)

	<-rcvr.done

	err = rcvr.Shutdown(ctx)
	require.NoError(t, err)

	logs := consumer.AllLogs()
	require.NotEmpty(t, logs)

	resourceLog := logs[0].ResourceLogs().At(0)

	// Verify resource-level attributes
	attrs := resourceLog.Resource().Attributes()
	ccID, ok := attrs.Get("identity_federation.id")
	require.True(t, ok)
	assert.Equal(t, "cc-azure-001", ccID.Str())

	// Verify log records contain Azure integrations
	logRecords := resourceLog.ScopeLogs().At(0).LogRecords()
	assert.GreaterOrEqual(t, logRecords.Len(), 1)

	policyTemplates := make(map[string]bool)
	for i := 0; i < logRecords.Len(); i++ {
		record := logRecords.At(i)

		// Every record should have azure as package name
		pkgName, ok := record.Attributes().Get("package.name")
		require.True(t, ok)
		assert.Equal(t, "azure", pkgName.Str())

		// Every record should have provider.type = azure
		provType, ok := record.Attributes().Get("provider.type")
		require.True(t, ok)
		assert.Equal(t, "azure", provType.Str())

		// account_type should be set from top-level config
		accType, ok := record.Attributes().Get("account_type")
		require.True(t, ok)
		assert.Equal(t, "single-account", accType.Str())

		// verification.verified_at should be present
		_, ok = record.Attributes().Get("verification.verified_at")
		assert.True(t, ok, "verification.verified_at should be present")

		if tmpl, ok := record.Attributes().Get("policy_template"); ok {
			policyTemplates[tmpl.Str()] = true
		}
	}

	assert.True(t, policyTemplates["activitylogs"], "expected activitylogs policy_template")
	assert.True(t, policyTemplates["auditlogs"], "expected auditlogs policy_template")
}

func TestReceiver_GCPIntegrations(t *testing.T) {
	config := &Config{
		IdentityFederationID:   "cc-gcp-001",
		IdentityFederationName: "GCP Connector",
		AccountType:            "single-account",
		VerificationID:         "verify-gcp-001",
		VerificationType:       "scheduled",
		Providers: ProvidersConfig{
			GCP: GCPProviderConfig{
				Credentials: GCPCredentials{
					Audience:            "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
					ServiceAccountEmail: "verifier@my-gcp-project-123.iam.gserviceaccount.com",
				},
			},
		},
		Policies: []PolicyConfig{
			{
				PolicyID:   "policy-gcp-1",
				PolicyName: "GCP Audit Monitoring",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate:  "audit",
						PackageName:     "gcp",
						PackagePolicyID: "pp-audit-001",
						PackageTitle:    "GCP",
						PackageVersion:  "1.2.0",
					},
					{
						PolicyTemplate: "pubsub",
						PackageName:    "gcp",
						PackageTitle:   "GCP",
					},
					{
						PolicyTemplate: "storage",
						PackageName:    "gcp",
						PackageTitle:   "GCP",
					},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	rcvr := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()
	err := rcvr.Start(ctx, nil)
	require.NoError(t, err)

	<-rcvr.done

	err = rcvr.Shutdown(ctx)
	require.NoError(t, err)

	logs := consumer.AllLogs()
	require.NotEmpty(t, logs)

	resourceLog := logs[0].ResourceLogs().At(0)

	// Verify verification type
	attrs := resourceLog.Resource().Attributes()
	vType, ok := attrs.Get("verification.type")
	require.True(t, ok)
	assert.Equal(t, "scheduled", vType.Str())

	logRecords := resourceLog.ScopeLogs().At(0).LogRecords()
	assert.GreaterOrEqual(t, logRecords.Len(), 1)

	policyTemplates := make(map[string]bool)
	for i := 0; i < logRecords.Len(); i++ {
		record := logRecords.At(i)

		pkgName, ok := record.Attributes().Get("package.name")
		require.True(t, ok)
		assert.Equal(t, "gcp", pkgName.Str())

		provType, ok := record.Attributes().Get("provider.type")
		require.True(t, ok)
		assert.Equal(t, "gcp", provType.Str())

		if tmpl, ok := record.Attributes().Get("policy_template"); ok {
			policyTemplates[tmpl.Str()] = true
		}
	}

	assert.True(t, policyTemplates["audit"], "expected audit policy_template")
	assert.True(t, policyTemplates["pubsub"], "expected pubsub policy_template")
	assert.True(t, policyTemplates["storage"], "expected storage policy_template")
}

func TestReceiver_MultiProviderIntegrations(t *testing.T) {
	config := &Config{
		IdentityFederationID:   "cc-multi-001",
		IdentityFederationName: "Multi-Identity Federation",
		AccountType:            "organization-account",
		VerificationID:         "verify-multi-001",
		VerificationType:       "on_demand",
		Providers: ProvidersConfig{
			AWS: AWSProviderConfig{
				Credentials: AWSCredentials{
					RoleARN:    "arn:aws:iam::123456789012:role/ElasticAgentRole",
					ExternalID: "elastic-test-external-id",
				},
			},
			Azure: AzureProviderConfig{
				Credentials: AzureCredentials{
					TenantID: "tenant-001",
					ClientID: "client-001",
				},
			},
			GCP: GCPProviderConfig{
				Credentials: GCPCredentials{
					Audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
				},
			},
		},
		Policies: []PolicyConfig{
			{
				PolicyID:   "policy-aws",
				PolicyName: "AWS Security",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate:  "cloudtrail",
						PackageName:     "aws",
						PackagePolicyID: "pp-ct-001",
						PackageTitle:    "AWS",
						PackageVersion:  "2.17.0",
					},
				},
			},
			{
				PolicyID:   "policy-azure",
				PolicyName: "Azure Monitoring",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate:  "activitylogs",
						PackageName:     "azure",
						PackagePolicyID: "pp-al-001",
						PackageTitle:    "Azure",
					},
				},
			},
			{
				PolicyID:   "policy-gcp",
				PolicyName: "GCP Audit",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate:  "audit",
						PackageName:     "gcp",
						PackagePolicyID: "pp-ga-001",
						PackageTitle:    "GCP",
					},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	rcvr := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()
	err := rcvr.Start(ctx, nil)
	require.NoError(t, err)

	<-rcvr.done

	err = rcvr.Shutdown(ctx)
	require.NoError(t, err)

	logs := consumer.AllLogs()
	require.NotEmpty(t, logs)

	logRecords := logs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.GreaterOrEqual(t, logRecords.Len(), 3, "expected at least one record per provider")

	// Collect providers, policy templates, and policy IDs seen across all records
	providers := make(map[string]bool)
	policyTemplates := make(map[string]bool)
	policyIDs := make(map[string]bool)
	packageNames := make(map[string]bool)

	for i := 0; i < logRecords.Len(); i++ {
		record := logRecords.At(i)

		if prov, ok := record.Attributes().Get("provider.type"); ok {
			providers[prov.Str()] = true
		}
		if tmpl, ok := record.Attributes().Get("policy_template"); ok {
			policyTemplates[tmpl.Str()] = true
		}
		if pid, ok := record.Attributes().Get("policy.id"); ok {
			policyIDs[pid.Str()] = true
		}
		if pkg, ok := record.Attributes().Get("package.name"); ok {
			packageNames[pkg.Str()] = true
		}

		// All records should have account_type = organization-account
		accType, ok := record.Attributes().Get("account_type")
		require.True(t, ok)
		assert.Equal(t, "organization-account", accType.Str())

		// All records should have verification.verified_at
		_, ok = record.Attributes().Get("verification.verified_at")
		assert.True(t, ok)
	}

	// Verify all three providers were covered
	assert.True(t, providers["aws"], "expected aws provider")
	assert.True(t, providers["azure"], "expected azure provider")
	assert.True(t, providers["gcp"], "expected gcp provider")

	// Verify all three package names
	assert.True(t, packageNames["aws"])
	assert.True(t, packageNames["azure"])
	assert.True(t, packageNames["gcp"])

	// Verify all three policy templates
	assert.True(t, policyTemplates["cloudtrail"])
	assert.True(t, policyTemplates["activitylogs"])
	assert.True(t, policyTemplates["audit"])

	// Verify all three policies
	assert.True(t, policyIDs["policy-aws"])
	assert.True(t, policyIDs["policy-azure"])
	assert.True(t, policyIDs["policy-gcp"])

}

func TestPermissionRegistry(t *testing.T) {
	registry := NewPermissionRegistry()

	t.Run("supported integration - no version (latest)", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "")
		require.NotNil(t, perms)
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)
		assert.NotEmpty(t, perms.Permissions)

		actionFound := false
		for _, p := range perms.Permissions {
			if p.Action == "cloudtrail:LookupEvents" {
				actionFound = true
				assert.True(t, p.Required)
				assert.Equal(t, MethodAPICall, p.Method)
				break
			}
		}
		assert.True(t, actionFound, "expected cloudtrail:LookupEvents permission")
	})

	t.Run("unsupported integration", func(t *testing.T) {
		perms := registry.GetPermissions("unknown_integration", "")
		assert.Nil(t, perms)
		assert.False(t, registry.IsSupported("unknown_integration"))
	})

	t.Run("all AWS integrations registered", func(t *testing.T) {
		awsIntegrations := []string{
			"aws_cloudtrail",
			"aws_guardduty",
			"aws_securityhub",
			"aws_s3",
			"aws_ec2",
			"aws_vpcflow",
			"aws_waf",
			"aws_route53",
			"aws_elb",
			"aws_cloudfront",
			"aws_cspm",
			"aws_asset_inventory",
		}

		for _, integration := range awsIntegrations {
			assert.True(t, registry.IsSupported(integration), "expected %s to be supported", integration)
			perms := registry.GetPermissions(integration, "")
			require.NotNil(t, perms, "expected permissions for %s", integration)
			assert.Equal(t, verifier.ProviderAWS, perms.Provider, "expected AWS provider for %s", integration)
		}
	})

	t.Run("Azure integrations registered", func(t *testing.T) {
		azureIntegrations := []string{
			"azure_activitylogs",
			"azure_auditlogs",
			"azure_blob_storage",
			"azure_cspm",
			"azure_asset_inventory",
		}

		for _, integration := range azureIntegrations {
			assert.True(t, registry.IsSupported(integration), "expected %s to be supported", integration)
			perms := registry.GetPermissions(integration, "")
			require.NotNil(t, perms, "expected permissions for %s", integration)
			assert.Equal(t, verifier.ProviderAzure, perms.Provider, "expected Azure provider for %s", integration)
		}
	})

	t.Run("GCP integrations registered", func(t *testing.T) {
		gcpIntegrations := []string{
			"gcp_audit",
			"gcp_storage",
			"gcp_pubsub",
			"gcp_cspm",
			"gcp_asset_inventory",
		}

		for _, integration := range gcpIntegrations {
			assert.True(t, registry.IsSupported(integration), "expected %s to be supported", integration)
			perms := registry.GetPermissions(integration, "")
			require.NotNil(t, perms, "expected permissions for %s", integration)
			assert.Equal(t, verifier.ProviderGCP, perms.Provider, "expected GCP provider for %s", integration)
		}
	})

	// t.Run("Okta integrations not registered (no verifier factory yet)", func(t *testing.T) {
	// 	assert.False(t, registry.IsSupported("okta_system"), "okta_system should not be registered without a verifier factory")
	// 	assert.False(t, registry.IsSupported("okta_users"), "okta_users should not be registered without a verifier factory")
	// })

	t.Run("supported integrations by provider", func(t *testing.T) {
		byProvider := registry.SupportedIntegrationsByProvider()
		assert.NotEmpty(t, byProvider[verifier.ProviderAWS])
		assert.NotEmpty(t, byProvider[verifier.ProviderAzure])
		assert.NotEmpty(t, byProvider[verifier.ProviderGCP])
		// assert.Empty(t, byProvider[verifier.ProviderOkta])
	})

	// Version-aware permission lookup tests
	t.Run("cloudtrail v2 - SQS permissions required", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "2.17.0")
		require.NotNil(t, perms)
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)

		// In v2+, sqs:ReceiveMessage and sqs:DeleteMessage should be required
		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.True(t, p.Required, "sqs:ReceiveMessage should be required in v2+")
			}
			if p.Action == "sqs:DeleteMessage" {
				assert.True(t, p.Required, "sqs:DeleteMessage should be required in v2+")
			}
		}
	})

	t.Run("cloudtrail v1 - SQS permissions optional", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "1.5.0")
		require.NotNil(t, perms)
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)

		// In v1.x, sqs:ReceiveMessage and sqs:DeleteMessage should be optional
		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.False(t, p.Required, "sqs:ReceiveMessage should be optional in v1.x")
			}
			if p.Action == "sqs:DeleteMessage" {
				assert.False(t, p.Required, "sqs:DeleteMessage should be optional in v1.x")
			}
		}
	})

	t.Run("cloudtrail no version - defaults to latest (v2+)", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "")
		require.NotNil(t, perms)

		// Should get v2+ permissions (latest)
		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.True(t, p.Required, "default (latest) should have sqs:ReceiveMessage required")
			}
		}
	})

	t.Run("cloudtrail invalid version - falls back to latest", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "not-a-version")
		require.NotNil(t, perms)
		// Should fall back to the first (latest) entry
		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.True(t, p.Required, "invalid version should fall back to latest")
			}
		}
	})

	t.Run("guardduty with version - matches >=0.0.0", func(t *testing.T) {
		perms := registry.GetPermissions("aws_guardduty", "3.0.0")
		require.NotNil(t, perms)
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)
	})

	t.Run("version constraints are returned", func(t *testing.T) {
		constraints := registry.GetVersionConstraints("aws_cloudtrail")
		require.NotNil(t, constraints)
		assert.Len(t, constraints, 2)
		assert.Equal(t, ">=2.0.0", constraints[0])
		assert.Equal(t, ">=1.0.0,<2.0.0", constraints[1])
	})

	t.Run("version constraints for unknown integration", func(t *testing.T) {
		constraints := registry.GetVersionConstraints("unknown_integration")
		assert.Nil(t, constraints)
	})

	// Pre-release version tests: fallback to release constraints
	t.Run("beta version falls back to release constraint", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "2.17.0-beta1")
		require.NotNil(t, perms, "2.17.0-beta1 should match via fallback to >=2.0.0")
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)

		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.True(t, p.Required, "beta version should fall back to v2+ permissions")
			}
		}
	})

	t.Run("beta.N version falls back to release constraint", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "2.17.0-beta.2")
		require.NotNil(t, perms, "2.17.0-beta.2 should match via fallback to >=2.0.0")
	})

	t.Run("preview version falls back to release constraint", func(t *testing.T) {
		perms := registry.GetPermissions("aws_guardduty", "3.0.0-preview05")
		require.NotNil(t, perms, "3.0.0-preview05 should match via fallback to >=0.0.0")
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)
	})

	t.Run("rc version falls back to v1 release constraint", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "1.5.0-rc1")
		require.NotNil(t, perms, "1.5.0-rc1 should match via fallback to >=1.0.0,<2.0.0")

		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.False(t, p.Required, "rc v1 should get v1 permissions (SQS optional)")
			}
		}
	})

	t.Run("boundary beta version matches release constraint", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "2.0.0-beta1")
		require.NotNil(t, perms, "2.0.0-beta1 should match via fallback to >=2.0.0")

		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.True(t, p.Required, "2.0.0-beta1 should get v2+ permissions")
			}
		}
	})

	t.Run("preview with timestamp suffix", func(t *testing.T) {
		perms := registry.GetPermissions("aws_guardduty", "2.26.0-preview-1747764883")
		require.NotNil(t, perms, "version with timestamp preview suffix should match")
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)
	})

	t.Run("version with build metadata", func(t *testing.T) {
		perms := registry.GetPermissions("aws_cloudtrail", "2.17.0+build123")
		require.NotNil(t, perms, "version with build metadata should match >=2.0.0")

		for _, p := range perms.Permissions {
			if p.Action == "sqs:ReceiveMessage" {
				assert.True(t, p.Required, "build metadata version should get v2+ permissions")
			}
		}
	})

	t.Run("0.x version treated as preview", func(t *testing.T) {
		perms := registry.GetPermissions("aws_guardduty", "0.5.0")
		require.NotNil(t, perms, "0.5.0 should match via fallback to >=0.0.0")
		assert.Equal(t, verifier.ProviderAWS, perms.Provider)
	})
}

func TestPermissionRegistry_TagSpecific(t *testing.T) {
	registry := &PermissionRegistry{
		integrations: make(map[string][]VersionedPermissions),
	}

	betaPerms := IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{Action: "test:BetaAction", Required: true, Method: MethodAPICall},
		},
	}
	previewPerms := IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{Action: "test:PreviewAction", Required: true, Method: MethodAPICall},
		},
	}
	rcPerms := IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{Action: "test:RCAction", Required: true, Method: MethodAPICall},
		},
	}
	releasePerms := IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{Action: "test:ReleaseAction", Required: true, Method: MethodAPICall},
		},
	}

	registry.registerWithTag("test_integration", ">=1.0.0", PrereleaseTagBeta, betaPerms)
	registry.registerWithTag("test_integration", ">=1.0.0", PrereleaseTagPreview, previewPerms)
	registry.registerWithTag("test_integration", ">=1.0.0", PrereleaseTagRC, rcPerms)
	registry.register("test_integration", ">=1.0.0", releasePerms)

	t.Run("beta version matches beta entry", func(t *testing.T) {
		perms := registry.GetPermissions("test_integration", "2.0.0-beta.1")
		require.NotNil(t, perms)
		require.Len(t, perms.Permissions, 1)
		assert.Equal(t, "test:BetaAction", perms.Permissions[0].Action)
	})

	t.Run("preview version matches preview entry", func(t *testing.T) {
		perms := registry.GetPermissions("test_integration", "2.0.0-preview01")
		require.NotNil(t, perms)
		require.Len(t, perms.Permissions, 1)
		assert.Equal(t, "test:PreviewAction", perms.Permissions[0].Action)
	})

	t.Run("rc version matches rc entry", func(t *testing.T) {
		perms := registry.GetPermissions("test_integration", "2.0.0-rc1")
		require.NotNil(t, perms)
		require.Len(t, perms.Permissions, 1)
		assert.Equal(t, "test:RCAction", perms.Permissions[0].Action)
	})

	t.Run("release version matches release entry", func(t *testing.T) {
		perms := registry.GetPermissions("test_integration", "2.0.0")
		require.NotNil(t, perms)
		require.Len(t, perms.Permissions, 1)
		assert.Equal(t, "test:ReleaseAction", perms.Permissions[0].Action)
	})

	t.Run("no version returns release entry", func(t *testing.T) {
		perms := registry.GetPermissions("test_integration", "")
		require.NotNil(t, perms)
		require.Len(t, perms.Permissions, 1)
		assert.Equal(t, "test:ReleaseAction", perms.Permissions[0].Action)
	})

	t.Run("invalid version returns release entry", func(t *testing.T) {
		perms := registry.GetPermissions("test_integration", "not-valid")
		require.NotNil(t, perms)
		require.Len(t, perms.Permissions, 1)
		assert.Equal(t, "test:ReleaseAction", perms.Permissions[0].Action)
	})

	t.Run("version constraints include tags", func(t *testing.T) {
		constraints := registry.GetVersionConstraints("test_integration")
		require.Len(t, constraints, 4)
		assert.Equal(t, ">=1.0.0 [beta]", constraints[0])
		assert.Equal(t, ">=1.0.0 [preview]", constraints[1])
		assert.Equal(t, ">=1.0.0 [rc]", constraints[2])
		assert.Equal(t, ">=1.0.0", constraints[3])
	})
}

func TestPermissionRegistry_TagFallback(t *testing.T) {
	registry := &PermissionRegistry{
		integrations: make(map[string][]VersionedPermissions),
	}

	betaPerms := IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{Action: "test:BetaOnly", Required: true, Method: MethodAPICall},
		},
	}
	releasePerms := IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{Action: "test:Release", Required: true, Method: MethodAPICall},
		},
	}

	registry.registerWithTag("test_fallback", ">=2.0.0", PrereleaseTagBeta, betaPerms)
	registry.register("test_fallback", ">=1.0.0", releasePerms)

	t.Run("beta version in range gets beta permissions", func(t *testing.T) {
		perms := registry.GetPermissions("test_fallback", "2.5.0-beta.1")
		require.NotNil(t, perms)
		assert.Equal(t, "test:BetaOnly", perms.Permissions[0].Action)
	})

	t.Run("beta version below tag range falls back to release", func(t *testing.T) {
		perms := registry.GetPermissions("test_fallback", "1.5.0-beta.1")
		require.NotNil(t, perms)
		assert.Equal(t, "test:Release", perms.Permissions[0].Action)
	})

	t.Run("preview version with no preview entry falls back to release", func(t *testing.T) {
		perms := registry.GetPermissions("test_fallback", "2.5.0-preview01")
		require.NotNil(t, perms)
		assert.Equal(t, "test:Release", perms.Permissions[0].Action)
	})

	t.Run("rc version with no rc entry falls back to release", func(t *testing.T) {
		perms := registry.GetPermissions("test_fallback", "2.5.0-rc1")
		require.NotNil(t, perms)
		assert.Equal(t, "test:Release", perms.Permissions[0].Action)
	})
}

func TestExtractPrereleaseTag(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"2.17.0", ""},
		{"2.17.0-beta1", PrereleaseTagBeta},
		{"2.17.0-beta.1", PrereleaseTagBeta},
		{"2.17.0-beta", PrereleaseTagBeta},
		{"3.3.0-preview05", PrereleaseTagPreview},
		{"3.3.0-preview.5", PrereleaseTagPreview},
		{"9.1.0-preview-1747764883", PrereleaseTagPreview},
		{"2.0.0-rc1", PrereleaseTagRC},
		{"2.0.0-rc.1", PrereleaseTagRC},
		{"1.0.0-alpha.1", PrereleaseTagBeta},
		{"1.0.0-SNAPSHOT", PrereleaseTagBeta},
		{"0.5.0", PrereleaseTagPreview},
		{"0.1.0-beta.1", PrereleaseTagPreview},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			v, err := semver.NewVersion(tt.version)
			require.NoError(t, err)
			assert.Equal(t, tt.want, extractPrereleaseTag(v))
		})
	}
}

func TestStripPrerelease(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"2.17.0", "2.17.0"},
		{"2.17.0-beta1", "2.17.0"},
		{"3.3.0-preview05", "3.3.0"},
		{"9.1.0-preview-1747764883", "9.1.0"},
		{"2.0.0-rc.1", "2.0.0"},
		{"2.17.0+build123", "2.17.0"},
		{"1.0.0-beta.1+build456", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			v, err := semver.NewVersion(tt.version)
			require.NoError(t, err)
			stripped := stripPrerelease(v)
			assert.Equal(t, tt.want, stripped.String())
		})
	}
}

func TestReceiver_FleetManagedStyle(t *testing.T) {
	config := &Config{
		IdentityFederationID:   "cc-fleet-001",
		IdentityFederationName: "Fleet Managed Connector",
		AccountType:            "single-account",
		VerificationID:         "verify-fleet-001",
		VerificationType:       "scheduled",
		Providers: ProvidersConfig{
			AWS: AWSProviderConfig{
				Credentials: AWSCredentials{
					RoleARN:    "arn:aws:iam::123456789012:role/ElasticAgentRole",
					ExternalID: "elastic-test-external-id",
				},
			},
		},
		Policies: []PolicyConfig{
			{
				PolicyID:   "policy-fleet-001",
				PolicyName: "Verifier-Policy-Fleet-Managed-Connector-abc12345",
				Integrations: []IntegrationConfig{
					{
						PolicyTemplate: "cloudtrail",
						PackageName:    "aws",
						PackageTitle:   "AWS",
						PackageVersion: "2.17.0",
					},
					{
						PolicyTemplate: "guardduty",
						PackageName:    "aws",
						PackageTitle:   "AWS",
						PackageVersion: "2.17.0",
					},
					{
						PolicyTemplate: "securityhub",
						PackageName:    "aws",
						PackageTitle:   "AWS",
						PackageVersion: "2.17.0",
					},
				},
			},
		},
	}

	consumer := &consumertest.LogsSink{}
	rcvr := newVerifierReceiver(
		receivertest.NewNopSettings(metadata.Type),
		config,
		consumer,
	)

	ctx := context.Background()
	err := rcvr.Start(ctx, nil)
	require.NoError(t, err)

	<-rcvr.done

	err = rcvr.Shutdown(ctx)
	require.NoError(t, err)

	logs := consumer.AllLogs()
	require.NotEmpty(t, logs)

	logRecords := logs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.GreaterOrEqual(t, logRecords.Len(), 1)

	policyTemplates := make(map[string]bool)
	for i := 0; i < logRecords.Len(); i++ {
		record := logRecords.At(i)

		policyID, ok := record.Attributes().Get("policy.id")
		require.True(t, ok)
		assert.Equal(t, "policy-fleet-001", policyID.Str())

		policyName, ok := record.Attributes().Get("policy.name")
		require.True(t, ok)
		assert.Contains(t, policyName.Str(), "Verifier-Policy-Fleet-Managed-Connector")

		if tmpl, ok := record.Attributes().Get("policy_template"); ok {
			policyTemplates[tmpl.Str()] = true
		}
	}

	assert.True(t, policyTemplates["cloudtrail"], "expected cloudtrail policy_template")
	assert.True(t, policyTemplates["guardduty"], "expected guardduty policy_template")
	assert.True(t, policyTemplates["securityhub"], "expected securityhub policy_template")
}
