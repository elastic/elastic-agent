// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver"

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"
)

// Config defines configuration for the permission verifier receiver.
// The receiver owns the mapping between integrations and their required permissions.
// Fleet API provides the policy/integration context; the receiver determines what
// permissions each integration needs and how to verify them.
type Config struct {
	// IdentityFederationID identifies the Identity Federation being verified.
	IdentityFederationID string `mapstructure:"identity_federation_id"`

	// IdentityFederationName is the human-readable name of the Identity Federation.
	IdentityFederationName string `mapstructure:"identity_federation_name"`

	// AccountType indicates whether the target is a single account or an
	// organization (management) account. Affects which permissions are verified.
	// Valid values: "single-account", "organization-account".
	AccountType string `mapstructure:"account_type"`

	// VerificationID is a unique identifier for this verification session.
	VerificationID string `mapstructure:"verification_id"`

	// VerificationType indicates the type of verification: "on_demand" or "scheduled".
	VerificationType string `mapstructure:"verification_type"`

	// Providers contains authentication configuration for each cloud/identity provider.
	Providers ProvidersConfig `mapstructure:"providers"`

	// Policies is the list of agent policies to verify.
	// Each policy contains integrations that need permission verification.
	Policies []PolicyConfig `mapstructure:"policies"`
}

// ProvidersConfig contains authentication configuration for all supported providers.
type ProvidersConfig struct {
	// IdentityFederation contains shared OIDC authentication used by the identity federation flow.
	IdentityFederation IdentityFederationConfig `mapstructure:"identity_federation"`

	AWS   AWSProviderConfig   `mapstructure:"aws"`
	Azure AzureProviderConfig `mapstructure:"azure"`
	GCP   GCPProviderConfig   `mapstructure:"gcp"`
	// Okta  OktaProviderConfig  `mapstructure:"okta"`
}

// IdentityFederationConfig contains shared OIDC fields for the identity federation
// authentication flow. These are typically injected as environment variables
// by the agentless controller.
type IdentityFederationConfig struct {
	// IDTokenFile is the path to the OIDC JWT token file.
	// Env fallback: CLOUD_CONNECTORS_ID_TOKEN_FILE
	IDTokenFile string `mapstructure:"id_token_file"`

	// GlobalRoleARN is the Elastic global IAM role used in the AWS/GCP auth chains.
	// Env fallback: CLOUD_CONNECTORS_GLOBAL_ROLE
	GlobalRoleARN string `mapstructure:"global_role_arn"`

	// CloudResourceID identifies the cloud resource, used as SourceIdentity.
	// Env fallback: CLOUD_RESOURCE_ID
	CloudResourceID string `mapstructure:"cloud_resource_id"`
}

// LoadFromEnv populates empty fields from well-known environment variables
// set by the agentless controller.
func (cfg *IdentityFederationConfig) LoadFromEnv() {
	if cfg.IDTokenFile == "" {
		cfg.IDTokenFile = os.Getenv("CLOUD_CONNECTORS_ID_TOKEN_FILE")
	}
	if cfg.GlobalRoleARN == "" {
		cfg.GlobalRoleARN = os.Getenv("CLOUD_CONNECTORS_GLOBAL_ROLE")
	}
	if cfg.CloudResourceID == "" {
		cfg.CloudResourceID = os.Getenv("CLOUD_RESOURCE_ID")
	}
}

// IsConfigured returns true if the identity federation OIDC token file is available.
func (cfg *IdentityFederationConfig) IsConfigured() bool {
	return cfg.IDTokenFile != ""
}

// AWSProviderConfig contains AWS authentication configuration.
type AWSProviderConfig struct {
	// Credentials contains the Identity Federation authentication credentials.
	Credentials AWSCredentials `mapstructure:"credentials"`
}

// AWSCredentials contains the AWS credentials for Identity Federation mode.
type AWSCredentials struct {
	// RoleARN is the ARN of the IAM role to assume in the customer's AWS account.
	RoleARN string `mapstructure:"role_arn"`

	// ExternalID is used to prevent confused deputy attacks.
	ExternalID string `mapstructure:"external_id"`

	// UseDefaultCredentials enables using default AWS credentials (for testing).
	UseDefaultCredentials bool `mapstructure:"use_default_credentials"`
}

// Validate validates the AWS credentials.
// Testing flow: set use_default_credentials to true.
// Production flow: both role_arn and external_id must be provided for identity federation.
func (cfg *AWSCredentials) Validate() error {
	if cfg.UseDefaultCredentials {
		return nil // testing flow
	}
	if cfg.RoleARN == "" && cfg.ExternalID == "" {
		return nil // not configured
	}
	if cfg.RoleARN == "" {
		return errors.New("role_arn must be specified")
	}
	if cfg.ExternalID == "" {
		return errors.New("external_id must be specified")
	}
	return nil
}

// IsConfigured returns true if AWS credentials are configured for either the
// testing flow (use_default_credentials) or the production flow (role_arn + external_id).
func (cfg *AWSCredentials) IsConfigured() bool {
	return cfg.UseDefaultCredentials || (cfg.RoleARN != "" && cfg.ExternalID != "")
}

// ToAuthConfig converts the config to a verifier.AWSAuthConfig, merging in
// the shared identity federation OIDC configuration.
func (cfg *AWSCredentials) ToAuthConfig(cc IdentityFederationConfig) verifier.AWSAuthConfig {
	return verifier.AWSAuthConfig{
		IDTokenFile:           cc.IDTokenFile,
		GlobalRoleARN:         cc.GlobalRoleARN,
		CloudResourceID:       cc.CloudResourceID,
		RoleARN:               cfg.RoleARN,
		ExternalID:            cfg.ExternalID,
		UseDefaultCredentials: cfg.UseDefaultCredentials,
	}
}

// AzureProviderConfig contains Azure authentication configuration.
type AzureProviderConfig struct {
	// Credentials contains the Azure authentication credentials.
	Credentials AzureCredentials `mapstructure:"credentials"`
}

// AzureCredentials contains the Azure credentials.
type AzureCredentials struct {
	TenantID string `mapstructure:"tenant_id"`
	ClientID string `mapstructure:"client_id"`

	// UseDefaultCredentials uses DefaultAzureCredential which chains env vars,
	// workload identity, managed identity, Azure CLI (az login), and azd CLI.
	UseDefaultCredentials bool `mapstructure:"use_default_credentials"`
}

// Validate validates the Azure credentials.
func (cfg *AzureCredentials) Validate() error {
	if cfg.UseDefaultCredentials {
		return nil
	}
	if cfg.TenantID == "" && cfg.ClientID == "" {
		return nil // not configured
	}
	if cfg.TenantID == "" {
		return errors.New("tenant_id must be specified")
	}
	if cfg.ClientID == "" {
		return errors.New("client_id must be specified")
	}
	return nil
}

// IsConfigured returns true if Azure credentials are configured.
func (cfg *AzureCredentials) IsConfigured() bool {
	return cfg.UseDefaultCredentials || (cfg.TenantID != "" && cfg.ClientID != "")
}

// ToAuthConfig converts the config to a verifier.AzureAuthConfig, merging in
// the shared identity federation OIDC configuration.
func (cfg *AzureCredentials) ToAuthConfig(cc IdentityFederationConfig) verifier.AzureAuthConfig {
	return verifier.AzureAuthConfig{
		IDTokenFile:           cc.IDTokenFile,
		TenantID:              cfg.TenantID,
		ClientID:              cfg.ClientID,
		UseDefaultCredentials: cfg.UseDefaultCredentials,
	}
}

// GCPProviderConfig contains GCP authentication configuration.
type GCPProviderConfig struct {
	// Credentials contains the GCP authentication credentials.
	Credentials GCPCredentials `mapstructure:"credentials"`
}

// GCPCredentials contains the GCP credentials.
type GCPCredentials struct {
	// Identity Federation WIF fields
	// Audience is the full resource name of the GCP WIF provider used as the
	// STS token exchange audience.
	// Example: //iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider
	Audience string `mapstructure:"audience"`

	// ServiceAccountEmail is the GCP service account to impersonate via WIF.
	// The project ID is derived from this email when set
	// (e.g. "sa@my-project.iam.gserviceaccount.com" → project "my-project").
	ServiceAccountEmail string `mapstructure:"service_account_email"`

	// UseDefaultCredentials uses Application Default Credentials (for testing).
	UseDefaultCredentials bool `mapstructure:"use_default_credentials"`
}

// projectID derives the GCP project identifier from the configured fields.
// It first tries to extract a human-readable project ID from the service account
// email (format: "name@PROJECT_ID.iam.gserviceaccount.com"). If that fails, it falls back to extracting the numeric project number
// from the audience resource name.  Both forms are accepted by all GCP APIs.
func (cfg *GCPCredentials) projectID() string {
	if id := gcpProjectIDFromServiceAccountEmail(cfg.ServiceAccountEmail); id != "" {
		return id
	}
	return gcpProjectNumberFromAudience(cfg.Audience)
}

// gcpProjectIDFromServiceAccountEmail extracts the GCP project ID from a
// service account email of the form "name@PROJECT_ID.iam.gserviceaccount.com".
// Returns an empty string when the email is empty or does not match the pattern.
func gcpProjectIDFromServiceAccountEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return ""
	}
	const suffix = ".iam.gserviceaccount.com"
	domain := email[at+1:]
	if !strings.HasSuffix(domain, suffix) {
		return ""
	}
	return strings.TrimSuffix(domain, suffix)
}

// gcpProjectNumberFromAudience extracts the numeric GCP project number from a
// Workload Identity Federation audience of the form:
//
//	//iam.googleapis.com/projects/PROJECT_NUMBER/locations/...
//
// Returns an empty string when the audience is empty or does not match the
// expected prefix. Note: this returns a project *number*, not a project ID
// (name); both are accepted by GCP APIs.
func gcpProjectNumberFromAudience(audience string) string {
	const prefix = "//iam.googleapis.com/projects/"
	if !strings.HasPrefix(audience, prefix) {
		return ""
	}
	rest := audience[len(prefix):]
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// Validate validates the GCP credentials.
// Testing flow: set use_default_credentials to true.
// Production flow: both audience and service_account_email must be provided for identity federation.
func (cfg *GCPCredentials) Validate() error {
	if cfg.UseDefaultCredentials {
		return nil // testing flow
	}
	if cfg.Audience == "" && cfg.ServiceAccountEmail == "" {
		return nil // not configured
	}
	if cfg.Audience == "" {
		return errors.New("audience must be specified")
	}
	if cfg.ServiceAccountEmail == "" {
		return errors.New("service_account_email must be specified")
	}
	return nil
}

// IsConfigured returns true if GCP credentials are configured for either the
// testing flow (use_default_credentials) or the production flow (audience + service_account_email).
func (cfg *GCPCredentials) IsConfigured() bool {
	return cfg.UseDefaultCredentials || (cfg.Audience != "" && cfg.ServiceAccountEmail != "")
}

// ToAuthConfig converts the config to a verifier.GCPAuthConfig, merging in
// the shared identity federation OIDC configuration. The project ID is derived
// from the service account email or, as a fallback, from the WIF audience.
func (cfg *GCPCredentials) ToAuthConfig(cc IdentityFederationConfig, identityFederationID string) verifier.GCPAuthConfig {
	return verifier.GCPAuthConfig{
		IDTokenFile:           cc.IDTokenFile,
		Audience:              cfg.Audience,
		ServiceAccountEmail:   cfg.ServiceAccountEmail,
		GlobalRoleARN:         cc.GlobalRoleARN,
		CloudResourceID:       cc.CloudResourceID,
		IdentityFederationID:  identityFederationID,
		ProjectID:             cfg.projectID(),
		UseDefaultCredentials: cfg.UseDefaultCredentials,
	}
}

// // OktaProviderConfig contains Okta authentication configuration.
// type OktaProviderConfig struct {
// 	// Credentials contains the Okta authentication credentials.
// 	Credentials OktaCredentials `mapstructure:"credentials"`
// }

// // OktaCredentials contains the Okta credentials.
// type OktaCredentials struct {
// 	// Domain is the Okta domain (e.g., dev-123456.okta.com).
// 	Domain string `mapstructure:"domain"`

// 	// APIToken is the Okta API token.
// 	APIToken string `mapstructure:"api_token"`

// 	// ClientID is the OAuth 2.0 client ID (for OAuth authentication).
// 	ClientID string `mapstructure:"client_id"`

// 	// PrivateKey is the private key for OAuth authentication.
// 	PrivateKey string `mapstructure:"private_key"`
// }

// // Validate validates the Okta credentials.
// func (cfg *OktaCredentials) Validate() error {
// 	if cfg.Domain == "" && cfg.APIToken == "" && cfg.ClientID == "" {
// 		return nil // Not configured
// 	}
// 	if cfg.Domain == "" {
// 		return errors.New("domain must be specified")
// 	}
// 	if cfg.APIToken == "" && cfg.ClientID == "" {
// 		return errors.New("either api_token or client_id must be specified")
// 	}
// 	if cfg.ClientID != "" && cfg.PrivateKey == "" {
// 		return errors.New("private_key must be specified when using client_id")
// 	}
// 	return nil
// }

// // IsConfigured returns true if Okta credentials are configured.
// func (cfg *OktaCredentials) IsConfigured() bool {
// 	return cfg.Domain != "" && (cfg.APIToken != "" || (cfg.ClientID != "" && cfg.PrivateKey != ""))
// }

// // ToAuthConfig converts the config to a verifier.OktaAuthConfig.
// func (cfg *OktaCredentials) ToAuthConfig() verifier.OktaAuthConfig {
// 	return verifier.OktaAuthConfig{
// 		Domain:     cfg.Domain,
// 		APIToken:   cfg.APIToken,
// 		ClientID:   cfg.ClientID,
// 		PrivateKey: cfg.PrivateKey,
// 	}
// }

// PolicyConfig represents an agent policy with its integrations.
type PolicyConfig struct {
	// PolicyID is the unique identifier for the policy.
	PolicyID string `mapstructure:"policy_id"`

	// PolicyName is the human-readable name of the policy.
	PolicyName string `mapstructure:"policy_name"`

	// Integrations is the list of integrations within this policy.
	Integrations []IntegrationConfig `mapstructure:"integrations"`
}

// IntegrationConfig represents an integration within a policy.
// Field names align with Fleet's package policy API vocabulary:
// the composite key is (PolicyTemplate, PackageName).
type IntegrationConfig struct {
	// PolicyTemplate is the policy template name from the integration package
	// (e.g., "cloudtrail", "guardduty", "activitylogs"). Combined with PackageName
	// to form the registry lookup key.
	PolicyTemplate string `mapstructure:"policy_template"`

	// PackageName is the integration package name (e.g., "aws", "azure", "gcp", "okta").
	PackageName string `mapstructure:"package_name"`

	// PackagePolicyID is the unique identifier for the package policy instance.
	PackagePolicyID string `mapstructure:"package_policy_id"`

	// PackageTitle is the human-readable title of the integration package (e.g., "AWS").
	PackageTitle string `mapstructure:"package_title"`

	// PackageVersion is the semantic version of the integration package (e.g., "2.17.0").
	// Different versions may require different permissions. When empty, the latest
	// registered permission set is used.
	PackageVersion string `mapstructure:"package_version"`

	// Config contains provider-specific configuration.
	// For AWS: may include regions, account_id, etc.
	Config map[string]interface{} `mapstructure:"config"`
}

// IntegrationType returns the registry lookup key derived from PackageName and
// PolicyTemplate (e.g., "aws" + "cloudtrail" -> "aws_cloudtrail").
func (cfg *IntegrationConfig) IntegrationType() string {
	return cfg.PackageName + "_" + cfg.PolicyTemplate
}

// Validate validates the configuration.
func (cfg *Config) Validate() error {
	if cfg.IdentityFederationID == "" {
		return errors.New("identity_federation_id must be specified")
	}
	if cfg.VerificationID == "" {
		return errors.New("verification_id must be specified")
	}
	if len(cfg.Policies) == 0 {
		return errors.New("at least one policy must be specified")
	}

	for i, policy := range cfg.Policies {
		if policy.PolicyID == "" {
			return fmt.Errorf("policies[%d]: policy_id must be specified", i)
		}
		if len(policy.Integrations) == 0 {
			return fmt.Errorf("policies[%d]: at least one integration must be specified", i)
		}
		for j, integration := range policy.Integrations {
			if integration.PolicyTemplate == "" {
				return fmt.Errorf("policies[%d].integrations[%d]: policy_template must be specified", i, j)
			}
			if integration.PackageName == "" {
				return fmt.Errorf("policies[%d].integrations[%d]: package_name must be specified", i, j)
			}
		}
	}

	// Provider credentials validation is handled by their respective Validate() methods
	// which are called automatically by the OTel framework.

	return nil
}

// GetProviderForPackage returns the provider type for a given package name.
func GetProviderForPackage(packageName string) verifier.ProviderType {
	switch packageName {
	case "aws":
		return verifier.ProviderAWS
	case "azure":
		return verifier.ProviderAzure
	case "gcp":
		return verifier.ProviderGCP
	// case "okta":
	// 	return verifier.ProviderOkta
	default:
		return ""
	}
}
