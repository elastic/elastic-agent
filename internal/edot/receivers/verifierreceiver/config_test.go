// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "valid config with AWS credentials",
			config: Config{
				IdentityFederationID:   "cc-12345",
				IdentityFederationName: "Production Connector",
				VerificationID:         "verify-abc123",
				VerificationType:       "on_demand",
				AccountType:            "single-account",
				Providers: ProvidersConfig{
					AWS: AWSProviderConfig{
						Credentials: AWSCredentials{
							RoleARN:    "arn:aws:iam::123456789012:role/ElasticAgentRole",
							ExternalID: "elastic-external-id-12345",
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
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid config with package version",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{
								PolicyTemplate: "cloudtrail",
								PackageName:    "aws",
								PackageVersion: "2.17.0",
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid config without AWS credentials (non-AWS integrations)",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{PolicyTemplate: "system", PackageName: "gcp"},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid config with AWS integration but no credentials (credentials optional at config level)",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{PolicyTemplate: "cloudtrail", PackageName: "aws"},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "invalid config - missing identity_federation_id",
			config: Config{
				VerificationID: "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{PolicyTemplate: "cloudtrail", PackageName: "aws"},
						},
					},
				},
			},
			wantErr: "identity_federation_id must be specified",
		},
		{
			name: "invalid config - missing verification_id",
			config: Config{
				IdentityFederationID: "cc-12345",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{PolicyTemplate: "cloudtrail", PackageName: "aws"},
						},
					},
				},
			},
			wantErr: "verification_id must be specified",
		},
		{
			name: "invalid config - no policies",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies:             []PolicyConfig{},
			},
			wantErr: "at least one policy must be specified",
		},
		{
			name: "invalid config - policy without policy_id",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies: []PolicyConfig{
					{
						Integrations: []IntegrationConfig{
							{PolicyTemplate: "cloudtrail", PackageName: "aws"},
						},
					},
				},
			},
			wantErr: "policies[0]: policy_id must be specified",
		},
		{
			name: "invalid config - policy without integrations",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID:     "policy-1",
						Integrations: []IntegrationConfig{},
					},
				},
			},
			wantErr: "policies[0]: at least one integration must be specified",
		},
		{
			name: "invalid config - integration without policy_template",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{PackageName: "aws"},
						},
					},
				},
			},
			wantErr: "policies[0].integrations[0]: policy_template must be specified",
		},
		{
			name: "invalid config - integration without package_name",
			config: Config{
				IdentityFederationID: "cc-12345",
				VerificationID:       "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{PolicyTemplate: "cloudtrail"},
						},
					},
				},
			},
			wantErr: "policies[0].integrations[0]: package_name must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAWSCredentials_Validate(t *testing.T) {
	tests := []struct {
		name        string
		credentials AWSCredentials
		wantErr     string
	}{
		{
			name: "valid - fully configured",
			credentials: AWSCredentials{
				RoleARN:    "arn:aws:iam::123456789012:role/ElasticAgentRole",
				ExternalID: "test-external-id",
			},
			wantErr: "",
		},
		{
			name:        "valid - empty (not configured)",
			credentials: AWSCredentials{},
			wantErr:     "",
		},
		{
			name: "valid - use_default_credentials",
			credentials: AWSCredentials{
				UseDefaultCredentials: true,
			},
			wantErr: "",
		},
		{
			name: "invalid - role_arn without external_id",
			credentials: AWSCredentials{
				RoleARN: "arn:aws:iam::123456789012:role/ElasticAgentRole",
			},
			wantErr: "external_id must be specified",
		},
		{
			name: "invalid - external_id without role_arn",
			credentials: AWSCredentials{
				ExternalID: "test-external-id",
			},
			wantErr: "role_arn must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.credentials.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAWSCredentials_IsConfigured(t *testing.T) {
	tests := []struct {
		name        string
		credentials AWSCredentials
		want        bool
	}{
		{
			name: "use_default_credentials",
			credentials: AWSCredentials{
				UseDefaultCredentials: true,
			},
			want: true,
		},
		{
			name: "role_arn only is not sufficient (external_id also required for production)",
			credentials: AWSCredentials{
				RoleARN: "arn:aws:iam::123456789012:role/ElasticAgentRole",
			},
			want: false,
		},
		{
			name: "role_arn with external_id (production flow)",
			credentials: AWSCredentials{
				RoleARN:    "arn:aws:iam::123456789012:role/ElasticAgentRole",
				ExternalID: "test-external-id",
			},
			want: true,
		},
		{
			name: "external_id alone is not sufficient",
			credentials: AWSCredentials{
				ExternalID: "test-external-id",
			},
			want: false,
		},
		{
			name:        "empty",
			credentials: AWSCredentials{},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.credentials.IsConfigured())
		})
	}
}

func TestGetProviderForPackage(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		want        verifier.ProviderType
	}{
		{
			name:        "AWS",
			packageName: "aws",
			want:        verifier.ProviderAWS,
		},
		{
			name:        "Azure",
			packageName: "azure",
			want:        verifier.ProviderAzure,
		},
		{
			name:        "GCP",
			packageName: "gcp",
			want:        verifier.ProviderGCP,
		},
		// {
		// 	name:        "Okta",
		// 	packageName: "okta",
		// 	want:        verifier.ProviderOkta,
		// },
		{
			name:        "Unknown",
			packageName: "unknown",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetProviderForPackage(tt.packageName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIntegrationConfig_IntegrationType(t *testing.T) {
	tests := []struct {
		name     string
		config   IntegrationConfig
		wantType string
	}{
		{
			name:     "AWS CloudTrail",
			config:   IntegrationConfig{PackageName: "aws", PolicyTemplate: "cloudtrail"},
			wantType: "aws_cloudtrail",
		},
		{
			name:     "Azure Activity Logs",
			config:   IntegrationConfig{PackageName: "azure", PolicyTemplate: "activitylogs"},
			wantType: "azure_activitylogs",
		},
		{
			name:     "GCP Audit",
			config:   IntegrationConfig{PackageName: "gcp", PolicyTemplate: "audit"},
			wantType: "gcp_audit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantType, tt.config.IntegrationType())
		})
	}
}

func TestGCPProjectIDFromServiceAccountEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "standard service account email",
			email: "my-sa@my-project-id.iam.gserviceaccount.com",
			want:  "my-project-id",
		},
		{
			name:  "hyphenated project ID",
			email: "verifier@elastic-cloud-prod.iam.gserviceaccount.com",
			want:  "elastic-cloud-prod",
		},
		{
			name:  "non-service-account email returns empty",
			email: "user@example.com",
			want:  "",
		},
		{
			name:  "empty email returns empty",
			email: "",
			want:  "",
		},
		{
			name:  "no at-sign returns empty",
			email: "noatsign",
			want:  "",
		},
		{
			name:  "wrong domain suffix returns empty",
			email: "sa@project.iam.googleapis.com",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, gcpProjectIDFromServiceAccountEmail(tt.email))
		})
	}
}

func TestGCPProjectNumberFromAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		want     string
	}{
		{
			name:     "full WIF provider resource name",
			audience: "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/pool/providers/provider",
			want:     "123456789",
		},
		{
			name:     "bare project prefix",
			audience: "//iam.googleapis.com/projects/987",
			want:     "987",
		},
		{
			name:     "wrong prefix returns empty",
			audience: "//iam.googleapis.com/organizations/123",
			want:     "",
		},
		{
			name:     "empty string returns empty",
			audience: "",
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, gcpProjectNumberFromAudience(tt.audience))
		})
	}
}

func TestGCPCredentials_Validate(t *testing.T) {
	tests := []struct {
		name        string
		credentials GCPCredentials
		wantErr     string
	}{
		{
			name:        "valid - empty (not configured)",
			credentials: GCPCredentials{},
			wantErr:     "",
		},
		{
			name: "valid - use_default_credentials (testing flow)",
			credentials: GCPCredentials{
				UseDefaultCredentials: true,
			},
			wantErr: "",
		},
		{
			name: "valid - fully configured (production flow)",
			credentials: GCPCredentials{
				Audience:            "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
				ServiceAccountEmail: "sa@my-project.iam.gserviceaccount.com",
			},
			wantErr: "",
		},
		{
			name: "invalid - audience without service_account_email",
			credentials: GCPCredentials{
				Audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
			},
			wantErr: "service_account_email must be specified",
		},
		{
			name: "invalid - service_account_email without audience",
			credentials: GCPCredentials{
				ServiceAccountEmail: "sa@my-project.iam.gserviceaccount.com",
			},
			wantErr: "audience must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.credentials.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGCPCredentials_IsConfigured(t *testing.T) {
	tests := []struct {
		name        string
		credentials GCPCredentials
		want        bool
	}{
		{
			name:        "empty",
			credentials: GCPCredentials{},
			want:        false,
		},
		{
			name: "use_default_credentials (testing flow)",
			credentials: GCPCredentials{
				UseDefaultCredentials: true,
			},
			want: true,
		},
		{
			name: "audience and service_account_email (production flow)",
			credentials: GCPCredentials{
				Audience:            "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
				ServiceAccountEmail: "sa@my-project.iam.gserviceaccount.com",
			},
			want: true,
		},
		{
			name: "audience only is not sufficient",
			credentials: GCPCredentials{
				Audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
			},
			want: false,
		},
		{
			name: "service_account_email only is not sufficient",
			credentials: GCPCredentials{
				ServiceAccountEmail: "sa@my-project.iam.gserviceaccount.com",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.credentials.IsConfigured())
		})
	}
}

func TestGCPCredentials_ProjectID(t *testing.T) {
	tests := []struct {
		name string
		cfg  GCPCredentials
		want string
	}{
		{
			name: "derived from service account email (preferred)",
			cfg: GCPCredentials{
				ServiceAccountEmail: "sa@my-project.iam.gserviceaccount.com",
				Audience:            "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/p",
			},
			want: "my-project",
		},
		{
			name: "fallback to WIF audience when no service account email",
			cfg: GCPCredentials{
				Audience: "//iam.googleapis.com/projects/987654321/locations/global/workloadIdentityPools/pool/providers/p",
			},
			want: "987654321",
		},
		{
			name: "non-service-account email falls back to WIF",
			cfg: GCPCredentials{
				ServiceAccountEmail: "user@example.com",
				Audience:            "//iam.googleapis.com/projects/555/locations/global/workloadIdentityPools/pool/providers/p",
			},
			want: "555",
		},
		{
			name: "use_default_credentials with no WIF returns empty (ADC provides project)",
			cfg: GCPCredentials{
				UseDefaultCredentials: true,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cfg.projectID())
		})
	}
}
