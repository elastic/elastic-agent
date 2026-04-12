// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package verifier provides permission verification for cloud providers.
// It defines interfaces and types for verifying permissions across different
// cloud providers (AWS, Azure, GCP) and identity providers (Okta, etc.).
package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ProviderType represents the type of cloud/identity provider.
type ProviderType string

const (
	ProviderAWS   ProviderType = "aws"
	ProviderAzure ProviderType = "azure"
	ProviderGCP   ProviderType = "gcp"
	// ProviderOkta  ProviderType = "okta"
)

// Result represents the result of a permission verification.
type Result struct {
	// Status is the verification result status.
	Status Status

	// ErrorCode is the error code returned by the provider (if any).
	ErrorCode string

	// ErrorMessage is the error message returned by the provider (if any).
	ErrorMessage string

	// Duration is how long the verification took.
	Duration time.Duration

	// Endpoint is the API endpoint that was called (if applicable).
	Endpoint string
}

// Status represents the result status of a permission verification.
type Status string

const (
	StatusGranted Status = "granted"
	StatusDenied  Status = "denied"
	StatusError   Status = "error"
	StatusSkipped Status = "skipped"
)

// VerificationMethod indicates how a permission should be verified.
type VerificationMethod string

const (
	MethodAPICall               VerificationMethod = "api_call"
	MethodDryRun                VerificationMethod = "dry_run"
	MethodHTTPProbe             VerificationMethod = "http_probe"
	MethodGraphQL               VerificationMethod = "graphql_query"
	MethodPolicyAttachmentCheck VerificationMethod = "policy_attachment_check"
)

// Permission represents a permission to verify.
type Permission struct {
	Action   string
	Method   VerificationMethod
	Required bool
	Category string
}

// ProviderConfig contains provider-specific configuration passed during verification.
type ProviderConfig struct {
	// AWS configuration
	Region    string
	AccountID string

	// Azure configuration
	ResourceGroup string
	TenantID      string

	// GCP configuration
	ProjectID string

	// // Okta configuration
	// OktaDomain string

	// Generic configuration
	Endpoint string
}

// AuthConfig is the interface for provider-specific authentication configuration.
// Each provider implements its own auth config struct.
type AuthConfig interface {
	// ProviderType returns the provider type this auth config is for.
	ProviderType() ProviderType
	// IsConfigured returns true if the auth config has the required fields.
	IsConfigured() bool
}

// AWSAuthConfig contains AWS authentication configuration.
//
// Identity Federation IRSA flow (when AWS_WEB_IDENTITY_TOKEN_FILE is set):
//
//	IRSA (implicit via LoadDefaultConfig) → AssumeRole(GlobalRoleARN) → AssumeRole(RoleARN, ExternalID)
//
// Identity Federation OIDC flow (when IDTokenFile is set):
//
//	JWT token file → WebIdentity(GlobalRoleARN) → AssumeRole(RoleARN, ExternalID)
//
// Default credentials flow (testing):
//
//	Uses the default credential chain (env vars, AWS_PROFILE, instance metadata).
type AWSAuthConfig struct {
	// Identity Federation fields — IDTokenFile is used for the OIDC flow; IRSA is
	// detected at runtime from AWS_WEB_IDENTITY_TOKEN_FILE.
	IDTokenFile     string // Path to the OIDC JWT token file (CLOUD_CONNECTORS_ID_TOKEN_FILE)
	GlobalRoleARN   string // Elastic global IAM role to assume
	CloudResourceID string // Resource ID used as SourceIdentity

	// Customer's AWS account (used in identity federation flow)
	RoleARN    string
	ExternalID string

	SessionName        string
	AssumeRoleDuration time.Duration

	// UseDefaultCredentials uses the default AWS credential chain (for testing).
	UseDefaultCredentials bool
}

func (c AWSAuthConfig) ProviderType() ProviderType { return ProviderAWS }

// IsIdentityFederation returns true when configured for identity federation
// (either IRSA or OIDC). Both flows require GlobalRoleARN and RoleARN; the
// actual auth method is detected at runtime from environment variables.
func (c AWSAuthConfig) IsIdentityFederation() bool {
	return c.GlobalRoleARN != "" && c.RoleARN != ""
}

func (c AWSAuthConfig) IsConfigured() bool {
	return c.IsIdentityFederation() || c.UseDefaultCredentials
}

// AzureAuthConfig contains Azure authentication configuration.
//
// Identity Federation flow (production):
//
//	JWT token file → ClientAssertionCredential(TenantID, ClientID) → Azure Token
//
// Default credentials flow (testing):
//
//	DefaultAzureCredential chains env vars, workload identity, managed identity,
//	Azure CLI (az login), and azd CLI.
type AzureAuthConfig struct {
	// Identity Federation OIDC field
	IDTokenFile string // Path to the OIDC JWT token file

	TenantID string
	ClientID string

	// UseDefaultCredentials uses DefaultAzureCredential (for testing).
	UseDefaultCredentials bool
}

func (c AzureAuthConfig) ProviderType() ProviderType { return ProviderAzure }

// IsIdentityFederation returns true when configured for the identity federation OIDC flow.
func (c AzureAuthConfig) IsIdentityFederation() bool {
	return c.IDTokenFile != "" && c.TenantID != "" && c.ClientID != ""
}

func (c AzureAuthConfig) IsConfigured() bool {
	return c.IsIdentityFederation() || c.UseDefaultCredentials
}

// GCPAuthConfig contains GCP authentication configuration.
//
// Identity Federation flow (production) — AWS-mediated WIF matching Cloudbeat:
//
//	JWT → AssumeRoleWithWebIdentity(GlobalRoleARN) → AWS creds →
//	GCP STS(Audience) → Service Account Impersonation
//
// Default credentials flow (testing):
//
//	Application Default Credentials (gcloud auth application-default login).
type GCPAuthConfig struct {
	// Identity Federation OIDC fields
	IDTokenFile         string // Path to the OIDC JWT token file
	Audience            string // Full resource name of the GCP WIF provider used as the STS exchange audience
	ServiceAccountEmail string // GCP service account to impersonate via WIF

	// AWS-mediated WIF fields (populated from IdentityFederationConfig)
	GlobalRoleARN        string // Elastic global AWS IAM role for the intermediate hop
	CloudResourceID      string // Resource ID used in AWS session naming
	IdentityFederationID string // Identity federation identifier for session naming

	ProjectID string

	// UseDefaultCredentials uses Application Default Credentials (for testing).
	UseDefaultCredentials bool
}

func (c GCPAuthConfig) ProviderType() ProviderType { return ProviderGCP }

// IsIdentityFederation returns true when configured for the identity federation
// AWS-mediated WIF flow (requires JWT, GCP WIF audience, and AWS global role).
func (c GCPAuthConfig) IsIdentityFederation() bool {
	return c.IDTokenFile != "" && c.Audience != "" && c.GlobalRoleARN != ""
}

func (c GCPAuthConfig) IsConfigured() bool {
	return c.IsIdentityFederation() || c.UseDefaultCredentials
}

// // OktaAuthConfig contains Okta authentication configuration.
// type OktaAuthConfig struct {
// 	// Domain is the Okta domain (e.g., dev-123456.okta.com).
// 	Domain string

// 	// APIToken is the Okta API token.
// 	APIToken string

// 	// ClientID is the OAuth 2.0 client ID (for OAuth authentication).
// 	ClientID string

// 	// PrivateKey is the private key for OAuth authentication.
// 	PrivateKey string
// }

// // ProviderType implements AuthConfig.
// func (c OktaAuthConfig) ProviderType() ProviderType { return ProviderOkta }

// // IsConfigured implements AuthConfig.
// func (c OktaAuthConfig) IsConfigured() bool {
// 	return c.Domain != "" && (c.APIToken != "" || (c.ClientID != "" && c.PrivateKey != ""))
// }

// Verifier is the interface for permission verifiers.
// Each cloud/identity provider implements this interface.
type Verifier interface {
	// Verify checks if a permission is granted.
	Verify(ctx context.Context, permission Permission, config ProviderConfig) Result

	// ProviderType returns the provider type this verifier handles.
	ProviderType() ProviderType

	// Close releases any resources held by the verifier.
	Close() error
}

// VerifierFactory is a function that creates a new Verifier instance.
type VerifierFactory func(ctx context.Context, logger *zap.Logger, authConfig AuthConfig) (Verifier, error)

// Registry manages verifier factories and instances.
// It allows registration of new verifier types and creation of verifier instances.
type Registry struct {
	mu        sync.RWMutex
	factories map[ProviderType]VerifierFactory
	verifiers map[ProviderType]Verifier
	logger    *zap.Logger
}

// NewRegistry creates a new verifier registry.
func NewRegistry(logger *zap.Logger) *Registry {
	return &Registry{
		factories: make(map[ProviderType]VerifierFactory),
		verifiers: make(map[ProviderType]Verifier),
		logger:    logger,
	}
}

// RegisterFactory registers a verifier factory for a provider type.
func (r *Registry) RegisterFactory(providerType ProviderType, factory VerifierFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[providerType] = factory
	r.logger.Debug("Registered verifier factory", zap.String("provider", string(providerType)))
}

// InitializeVerifier creates and stores a verifier for the given provider type and auth config.
func (r *Registry) InitializeVerifier(ctx context.Context, authConfig AuthConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	providerType := authConfig.ProviderType()
	factory, ok := r.factories[providerType]
	if !ok {
		return fmt.Errorf("no factory registered for provider type: %s", providerType)
	}

	verifier, err := factory(ctx, r.logger, authConfig)
	if err != nil {
		return fmt.Errorf("failed to create verifier for %s: %w", providerType, err)
	}

	r.verifiers[providerType] = verifier
	r.logger.Info("Initialized verifier", zap.String("provider", string(providerType)))
	return nil
}

// GetVerifier returns the verifier for a provider type, or nil if not initialized.
func (r *Registry) GetVerifier(providerType ProviderType) Verifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.verifiers[providerType]
}

// HasVerifier returns true if a verifier is initialized for the provider type.
func (r *Registry) HasVerifier(providerType ProviderType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.verifiers[providerType]
	return ok
}

// Close closes all initialized verifiers.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for providerType, verifier := range r.verifiers {
		if err := verifier.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close %s verifier: %w", providerType, err))
		}
	}
	r.verifiers = make(map[ProviderType]Verifier)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing verifiers: %v", errs)
	}
	return nil
}

// RegisteredProviders returns the list of provider types with registered factories.
func (r *Registry) RegisteredProviders() []ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]ProviderType, 0, len(r.factories))
	for p := range r.factories {
		providers = append(providers, p)
	}
	return providers
}

// InitializedProviders returns the list of provider types with initialized verifiers.
func (r *Registry) InitializedProviders() []ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]ProviderType, 0, len(r.verifiers))
	for p := range r.verifiers {
		providers = append(providers, p)
	}
	return providers
}
