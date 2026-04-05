// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver"

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"
)

const (
	scopeName    = "elastic.permission_verification"
	scopeVersion = "1.0.0"
	serviceName  = "permission-verifier"
)

// verifierReceiver implements the receiver.Logs interface.
// It verifies permissions for cloud integrations and reports results as OTEL logs.
// The receiver owns the mapping between integrations and their required permissions.
type verifierReceiver struct {
	params             receiver.Settings
	config             *Config
	consumer           consumer.Logs
	logger             *zap.Logger
	permissionRegistry *PermissionRegistry

	// Verifier registry manages verifiers for all cloud/identity providers
	verifierRegistry *verifier.Registry

	cancelFn context.CancelFunc
	wg       sync.WaitGroup

	// done is closed when verification completes (used for testing)
	done chan struct{}
}

// newVerifierReceiver creates a new verifier receiver.
func newVerifierReceiver(
	params receiver.Settings,
	config *Config,
	consumer consumer.Logs,
) *verifierReceiver {
	// Create verifier registry and register available factories
	verifierRegistry := verifier.NewRegistry(params.Logger)

	// Register verifier factories for all supported providers
	verifierRegistry.RegisterFactory(verifier.ProviderAWS, verifier.NewAWSVerifierFactory())
	verifierRegistry.RegisterFactory(verifier.ProviderAzure, verifier.NewAzureVerifierFactory())
	verifierRegistry.RegisterFactory(verifier.ProviderGCP, verifier.NewGCPVerifierFactory())
	// Future: Register Okta verifier factory when implemented
	// verifierRegistry.RegisterFactory(verifier.ProviderOkta, verifier.NewOktaVerifierFactory())

	return &verifierReceiver{
		params:             params,
		config:             config,
		consumer:           consumer,
		logger:             params.Logger,
		permissionRegistry: NewPermissionRegistry(),
		verifierRegistry:   verifierRegistry,
		done:               make(chan struct{}),
	}
}

// Start begins the permission verification process.
func (r *verifierReceiver) Start(ctx context.Context, _ component.Host) error {
	r.logger.Info("Starting verifier receiver",
		zap.String("identity_federation_id", r.config.IdentityFederationID),
		zap.String("verification_id", r.config.VerificationID),
		zap.Int("policy_count", len(r.config.Policies)),
	)

	// Initialize verifiers for configured providers
	r.initializeVerifiers(ctx)

	// Use context.Background() as parent because the Start() ctx is startup-scoped
	// and may be cancelled after Start returns, which would abort verification.
	startCtx, cancelFn := context.WithCancel(context.Background())
	r.cancelFn = cancelFn

	// Run verification
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.runVerification(startCtx)
	}()

	return nil
}

// initializeVerifiers initializes verifiers for all configured providers.
func (r *verifierReceiver) initializeVerifiers(ctx context.Context) {
	// Populate identity federation fields from environment variables when not
	// already set in the config. The agentless controller injects these as
	// pod env vars (IDENTITY_FEDERATION_ID_TOKEN_FILE, etc.).
	r.config.Providers.IdentityFederation.LoadFromEnv()
	idf := r.config.Providers.IdentityFederation

	if idf.IsConfigured() {
		r.logger.Info("Identity federation OIDC configuration detected",
			zap.String("id_token_file", idf.IDTokenFile),
			zap.Bool("has_global_role", idf.GlobalRoleARN != ""),
			zap.Bool("has_resource_id", idf.CloudResourceID != ""),
		)
	}

	// Initialize AWS verifier if configured
	if r.config.Providers.AWS.Credentials.IsConfigured() {
		authCfg := r.config.Providers.AWS.Credentials.ToAuthConfig(idf)
		if authCfg.IsIdentityFederation() {
			r.logger.Info("Initializing AWS verifier with identity federation OIDC flow",
				zap.String("role_arn", authCfg.RoleARN),
			)
		} else {
			r.logger.Info("Initializing AWS verifier with default credentials (testing)")
		}

		if err := r.verifierRegistry.InitializeVerifier(ctx, authCfg); err != nil {
			r.logger.Warn("Failed to initialize AWS verifier", zap.Error(err))
		} else {
			r.logger.Info("AWS verifier initialized successfully")
		}
	} else {
		r.logger.Debug("AWS credentials not configured")
	}

	// Initialize Azure verifier if configured
	if r.config.Providers.Azure.Credentials.IsConfigured() {
		authCfg := r.config.Providers.Azure.Credentials.ToAuthConfig(idf)
		if authCfg.IsIdentityFederation() {
			r.logger.Info("Initializing Azure verifier with identity federation OIDC flow",
				zap.String("tenant_id", authCfg.TenantID),
			)
		} else {
			r.logger.Info("Initializing Azure verifier with default credentials (testing)")
		}

		if err := r.verifierRegistry.InitializeVerifier(ctx, authCfg); err != nil {
			r.logger.Warn("Failed to initialize Azure verifier", zap.Error(err))
		} else {
			r.logger.Info("Azure verifier initialized successfully")
		}
	} else {
		r.logger.Debug("Azure credentials not configured")
	}

	// Initialize GCP verifier if configured
	if r.config.Providers.GCP.Credentials.IsConfigured() {
		authCfg := r.config.Providers.GCP.Credentials.ToAuthConfig(idf, r.config.IdentityFederationID)
		if authCfg.IsIdentityFederation() {
			r.logger.Info("Initializing GCP verifier with identity federation WIF flow",
				zap.String("project_id", authCfg.ProjectID),
			)
		} else {
			r.logger.Info("Initializing GCP verifier with default credentials (testing)")
		}

		if err := r.verifierRegistry.InitializeVerifier(ctx, authCfg); err != nil {
			r.logger.Warn("Failed to initialize GCP verifier", zap.Error(err))
		} else {
			r.logger.Info("GCP verifier initialized successfully")
		}
	} else {
		r.logger.Debug("GCP credentials not configured")
	}

	// // Initialize Okta verifier if configured
	// if r.config.Providers.Okta.Credentials.IsConfigured() {
	// 	r.logger.Info("Initializing Okta verifier",
	// 		zap.String("domain", r.config.Providers.Okta.Credentials.Domain),
	// 	)

	// 	if err := r.verifierRegistry.InitializeVerifier(ctx, r.config.Providers.Okta.Credentials.ToAuthConfig()); err != nil {
	// 		r.logger.Warn("Failed to initialize Okta verifier", zap.Error(err))
	// 	} else {
	// 		r.logger.Info("Okta verifier initialized successfully")
	// 	}
	// } else {
	// 	r.logger.Debug("Okta credentials not configured")
	// }

	// Log summary of initialized verifiers
	initialized := r.verifierRegistry.InitializedProviders()
	if len(initialized) > 0 {
		providers := make([]string, len(initialized))
		for i, p := range initialized {
			providers[i] = string(p)
		}
		r.logger.Info("Verifiers initialized", zap.Strings("providers", providers))
	} else {
		r.logger.Warn("No verifiers initialized - permission verification will be limited")
	}
}

// Shutdown stops the permission verification process.
func (r *verifierReceiver) Shutdown(ctx context.Context) error {
	r.logger.Info("Shutting down verifier receiver")
	if r.cancelFn != nil {
		r.cancelFn()
	}

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		r.logger.Warn("Shutdown deadline exceeded while waiting for verification to complete")
	}

	// Close all verifiers
	if err := r.verifierRegistry.Close(); err != nil {
		r.logger.Warn("Error closing verifiers", zap.Error(err))
	}

	return nil
}

// runVerification runs the permission verification for all configured policies.
func (r *verifierReceiver) runVerification(ctx context.Context) {
	defer close(r.done)
	if err := r.verifyPermissions(ctx); err != nil {
		r.logger.Error("Failed to verify permissions", zap.Error(err))
	}
}

// verifyPermissions performs permission verification for all policies and integrations.
// For each integration, it looks up required permissions from the registry and emits
// OTEL log records with structured results.
func (r *verifierReceiver) verifyPermissions(ctx context.Context) error {
	r.logger.Info("Starting permission verification",
		zap.String("identity_federation_id", r.config.IdentityFederationID),
		zap.String("verification_id", r.config.VerificationID),
		zap.Int("policy_count", len(r.config.Policies)),
	)

	now := time.Now()
	timestamp := pcommon.NewTimestampFromTime(now)
	verificationTimestamp := now.UTC().Format(time.RFC3339)

	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()

	// Set resource attributes per RFC specification
	resource := resourceLogs.Resource()
	resource.Attributes().PutStr("identity_federation.id", r.config.IdentityFederationID)
	if r.config.IdentityFederationName != "" {
		resource.Attributes().PutStr("identity_federation.name", r.config.IdentityFederationName)
	}

	resource.Attributes().PutStr("verification.id", r.config.VerificationID)
	resource.Attributes().PutStr("verification.timestamp", verificationTimestamp)
	verificationType := r.config.VerificationType
	if verificationType == "" {
		verificationType = "on_demand"
	}
	resource.Attributes().PutStr("verification.type", verificationType)
	resource.Attributes().PutStr("service.name", serviceName)
	resource.Attributes().PutStr("service.version", scopeVersion)

	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().SetName(scopeName)
	scopeLogs.Scope().SetVersion(scopeVersion)

	// Iterate through all policies and their integrations
	for _, policy := range r.config.Policies {
		r.logger.Debug("Processing policy",
			zap.String("policy_id", policy.PolicyID),
			zap.String("policy_name", policy.PolicyName),
			zap.Int("integration_count", len(policy.Integrations)),
		)

		for _, integration := range policy.Integrations {
			integrationType := integration.IntegrationType()
			r.logger.Debug("Processing integration",
				zap.String("policy_template", integration.PolicyTemplate),
				zap.String("package_name", integration.PackageName),
				zap.String("package_version", integration.PackageVersion),
			)

			// Look up required permissions from registry (version-aware)
			integrationPerms := r.permissionRegistry.GetPermissions(integrationType, integration.PackageVersion)
			if integrationPerms == nil {
				// Unknown integration type or unsupported version - emit a warning log
				r.emitUnsupportedIntegrationLog(
					scopeLogs,
					timestamp,
					policy,
					integration,
				)
				continue
			}

			// Verify and emit a log record for each permission
			for _, perm := range integrationPerms.Permissions {
				result := r.verifyPermission(ctx, integrationPerms.Provider, perm, integration)
				r.emitPermissionCheckLog(
					scopeLogs,
					timestamp,
					policy,
					integration,
					integrationPerms.Provider,
					perm,
					result,
				)
			}
		}
	}

	// Send logs to the consumer
	if scopeLogs.LogRecords().Len() > 0 {
		if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
			return fmt.Errorf("failed to consume logs: %w", err)
		}
		r.logger.Info("Permission verification logs emitted",
			zap.Int("log_count", scopeLogs.LogRecords().Len()),
		)
	}

	return nil
}

// verifyPermission verifies a single permission using the appropriate provider verifier.
func (r *verifierReceiver) verifyPermission(
	ctx context.Context,
	provider verifier.ProviderType,
	perm Permission,
	integration IntegrationConfig,
) verifier.Result {
	// Build provider config from integration config
	providerCfg := verifier.ProviderConfig{}

	// AWS-specific config
	if region, ok := integration.Config["region"].(string); ok {
		providerCfg.Region = region
	}
	if accountID, ok := integration.Config["account_id"].(string); ok {
		providerCfg.AccountID = accountID
	}

	// Azure-specific config
	if resourceGroup, ok := integration.Config["resource_group"].(string); ok {
		providerCfg.ResourceGroup = resourceGroup
	}
	if tenantID, ok := integration.Config["tenant_id"].(string); ok {
		providerCfg.TenantID = tenantID
	}

	// GCP-specific config
	if projectID, ok := integration.Config["project_id"].(string); ok {
		providerCfg.ProjectID = projectID
	}

	// // Okta-specific config
	// if domain, ok := integration.Config["domain"].(string); ok {
	// 	providerCfg.OktaDomain = domain
	// }

	// Get the verifier for this provider
	v := r.verifierRegistry.GetVerifier(provider)
	if v == nil {
		return verifier.Result{
			Status:       verifier.StatusError,
			ErrorCode:    "VerifierNotInitialized",
			ErrorMessage: fmt.Sprintf("%s verifier not initialized - credentials not configured", provider),
		}
	}

	return v.Verify(ctx, verifier.Permission{
		Action:   perm.Action,
		Method:   perm.Method,
		Required: perm.Required,
		Category: perm.Category,
	}, providerCfg)
}

// emitPermissionCheckLog emits a log record for a single permission check.
// The log record follows the RFC structure with all required attributes.
func (r *verifierReceiver) emitPermissionCheckLog(
	scopeLogs plog.ScopeLogs,
	timestamp pcommon.Timestamp,
	policy PolicyConfig,
	integration IntegrationConfig,
	provider verifier.ProviderType,
	perm Permission,
	result verifier.Result,
) {
	logRecord := scopeLogs.LogRecords().AppendEmpty()
	logRecord.SetTimestamp(timestamp)
	logRecord.SetObservedTimestamp(timestamp)

	// Determine severity based on verification result
	var severityNumber plog.SeverityNumber
	var severityText string
	var status PermissionStatus

	switch result.Status {
	case verifier.StatusGranted:
		severityNumber = plog.SeverityNumberInfo
		severityText = "INFO"
		status = StatusGranted
	case verifier.StatusDenied:
		if perm.Required {
			severityNumber = plog.SeverityNumberError
			severityText = "ERROR"
		} else {
			severityNumber = plog.SeverityNumberWarn
			severityText = "WARN"
		}
		status = StatusDenied
	case verifier.StatusError:
		severityNumber = plog.SeverityNumberError
		severityText = "ERROR"
		status = StatusError
	case verifier.StatusSkipped:
		severityNumber = plog.SeverityNumberInfo
		severityText = "INFO"
		status = StatusSkipped
	default:
		severityNumber = plog.SeverityNumberInfo
		severityText = "INFO"
		status = StatusPending
	}

	logRecord.SetSeverityNumber(severityNumber)
	logRecord.SetSeverityText(severityText)

	// Set the log body with human-readable summary
	body := fmt.Sprintf("Permission check: %s/%s - %s", provider, perm.Action, status)
	logRecord.Body().SetStr(body)

	// Set log attributes per RFC specification
	attrs := logRecord.Attributes()

	// Policy context
	attrs.PutStr("policy.id", policy.PolicyID)
	if policy.PolicyName != "" {
		attrs.PutStr("policy.name", policy.PolicyName)
	}

	// Integration context (Fleet package metadata)
	attrs.PutStr("policy_template", integration.PolicyTemplate)
	attrs.PutStr("package.name", integration.PackageName)
	if integration.PackageTitle != "" {
		attrs.PutStr("package.title", integration.PackageTitle)
	}
	if integration.PackageVersion != "" {
		attrs.PutStr("package.version", integration.PackageVersion)
	} else {
		attrs.PutStr("package.version", "unspecified")
	}
	if integration.PackagePolicyID != "" {
		attrs.PutStr("package_policy.id", integration.PackagePolicyID)
	}

	// Provider context
	attrs.PutStr("provider.type", string(provider))
	if r.config.AccountType != "" {
		attrs.PutStr("account_type", r.config.AccountType)
	}
	if accountID, ok := integration.Config["account_id"].(string); ok && accountID != "" {
		attrs.PutStr("provider.account", accountID)
	}
	if region, ok := integration.Config["region"].(string); ok && region != "" {
		attrs.PutStr("provider.region", region)
	}
	if projectID, ok := integration.Config["project_id"].(string); ok && projectID != "" {
		attrs.PutStr("provider.project_id", projectID)
	}

	// Permission details
	attrs.PutStr("permission.action", perm.Action)
	if perm.Category != "" {
		attrs.PutStr("permission.category", perm.Category)
	}
	attrs.PutStr("permission.status", string(status))
	attrs.PutBool("permission.required", perm.Required)

	// Error details (if any)
	if result.ErrorCode != "" {
		attrs.PutStr("permission.error_code", result.ErrorCode)
	}
	if result.ErrorMessage != "" {
		attrs.PutStr("permission.error_message", result.ErrorMessage)
	}

	// Verification metadata
	attrs.PutStr("verification.method", string(perm.Method))
	if result.Endpoint != "" {
		attrs.PutStr("verification.endpoint", result.Endpoint)
	}
	attrs.PutInt("verification.duration_ms", result.Duration.Milliseconds())
	attrs.PutStr("verification.verified_at", time.Now().UTC().Format(time.RFC3339))

	r.logger.Debug("Emitted permission check log",
		zap.String("policy_id", policy.PolicyID),
		zap.String("integration_type", integration.IntegrationType()),
		zap.String("permission", perm.Action),
		zap.String("status", string(status)),
		zap.Duration("duration", result.Duration),
	)
}

// emitUnsupportedIntegrationLog emits a warning log for unsupported integration types.
func (r *verifierReceiver) emitUnsupportedIntegrationLog(
	scopeLogs plog.ScopeLogs,
	timestamp pcommon.Timestamp,
	policy PolicyConfig,
	integration IntegrationConfig,
) {
	logRecord := scopeLogs.LogRecords().AppendEmpty()
	logRecord.SetTimestamp(timestamp)
	logRecord.SetObservedTimestamp(timestamp)
	logRecord.SetSeverityNumber(plog.SeverityNumberWarn)
	logRecord.SetSeverityText("WARN")

	integrationType := integration.IntegrationType()

	// Distinguish between unsupported type and unsupported version
	var body string
	var errorCode string
	if r.permissionRegistry.IsSupported(integrationType) {
		body = fmt.Sprintf("Unsupported integration version: %s@%s - skipping permission verification",
			integrationType, integration.PackageVersion)
		errorCode = "UnsupportedVersion"
	} else {
		body = fmt.Sprintf("Unsupported integration type: %s - skipping permission verification",
			integrationType)
		errorCode = "UnsupportedIntegration"
	}
	logRecord.Body().SetStr(body)

	attrs := logRecord.Attributes()
	attrs.PutStr("policy.id", policy.PolicyID)
	if policy.PolicyName != "" {
		attrs.PutStr("policy.name", policy.PolicyName)
	}
	attrs.PutStr("policy_template", integration.PolicyTemplate)
	attrs.PutStr("package.name", integration.PackageName)
	if integration.PackageTitle != "" {
		attrs.PutStr("package.title", integration.PackageTitle)
	}
	if integration.PackageVersion != "" {
		attrs.PutStr("package.version", integration.PackageVersion)
	} else {
		attrs.PutStr("package.version", "unspecified")
	}
	if integration.PackagePolicyID != "" {
		attrs.PutStr("package_policy.id", integration.PackagePolicyID)
	}
	attrs.PutStr("permission.status", string(StatusSkipped))
	attrs.PutStr("permission.error_code", errorCode)

	r.logger.Warn("Unsupported integration",
		zap.String("integration_type", integrationType),
		zap.String("package_version", integration.PackageVersion),
		zap.String("error_code", errorCode),
		zap.String("policy_id", policy.PolicyID),
	)
}
