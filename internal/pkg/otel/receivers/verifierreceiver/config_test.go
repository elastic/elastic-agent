// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/otel/receivers/verifierreceiver/internal/verifier"
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
				CloudConnectorID:   "cc-12345",
				CloudConnectorName: "Production Connector",
				VerificationID:     "verify-abc123",
				VerificationType:   "on_demand",
				AccountType:        "single_account",
				Providers: ProvidersConfig{
					AWS: AWSProviderConfig{
						Credentials: AWSCredentials{
							RoleARN:       "arn:aws:iam::123456789012:role/ElasticAgentRole",
							ExternalID:    "elastic-external-id-12345",
							DefaultRegion: "us-east-1",
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
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
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
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
				Policies: []PolicyConfig{
					{
						PolicyID: "policy-1",
						Integrations: []IntegrationConfig{
							{PolicyTemplate: "system", PackageName: "okta"},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid config with AWS integration but no credentials (credentials optional at config level)",
			config: Config{
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
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
			name: "invalid config - missing cloud_connector_id",
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
			wantErr: "cloud_connector_id must be specified",
		},
		{
			name: "invalid config - missing verification_id",
			config: Config{
				CloudConnectorID: "cc-12345",
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
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
				Policies:         []PolicyConfig{},
			},
			wantErr: "at least one policy must be specified",
		},
		{
			name: "invalid config - policy without policy_id",
			config: Config{
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
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
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
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
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
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
				CloudConnectorID: "cc-12345",
				VerificationID:   "verify-abc123",
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
				RoleARN:       "arn:aws:iam::123456789012:role/ElasticAgentRole",
				ExternalID:    "test-external-id",
				DefaultRegion: "us-east-1",
			},
			wantErr: "",
		},
		{
			name:        "valid - empty (not configured)",
			credentials: AWSCredentials{},
			wantErr:     "",
		},
		{
			name: "valid - only default_region (considered empty)",
			credentials: AWSCredentials{
				DefaultRegion: "us-east-1",
			},
			wantErr: "",
		},
		{
			name: "valid - use_default_credentials",
			credentials: AWSCredentials{
				UseDefaultCredentials: true,
			},
			wantErr: "",
		},
		{
			name: "valid - role_arn without external_id (cloud connector provides global role)",
			credentials: AWSCredentials{
				RoleARN: "arn:aws:iam::123456789012:role/ElasticAgentRole",
			},
			wantErr: "",
		},
		{
			name: "invalid - external_id without role_arn",
			credentials: AWSCredentials{
				ExternalID: "test-external-id",
			},
			wantErr: "role_arn must be specified when external_id is set",
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
			name: "role_arn only (cloud connector will supply OIDC chain)",
			credentials: AWSCredentials{
				RoleARN: "arn:aws:iam::123456789012:role/ElasticAgentRole",
			},
			want: true,
		},
		{
			name: "role_arn with external_id (cloud connector mode)",
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
		{
			name:        "Okta",
			packageName: "okta",
			want:        verifier.ProviderOkta,
		},
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
		name           string
		config         IntegrationConfig
		wantType       string
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
