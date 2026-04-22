// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	libbeatgcp "github.com/elastic/beats/v7/x-pack/libbeat/common/identityfederation/gcp"
)

// GCPVerifier implements permission verification for GCP.
type GCPVerifier struct {
	logger              *zap.Logger
	opts                []option.ClientOption
	httpClient          *http.Client
	configured          bool
	authConfig          GCPAuthConfig
	projectID           string
	serviceAccountEmail string
}

var _ Verifier = (*GCPVerifier)(nil)

// NewGCPVerifierFactory returns a factory function for creating GCP verifiers.
func NewGCPVerifierFactory() VerifierFactory {
	return func(ctx context.Context, logger *zap.Logger, authConfig AuthConfig) (Verifier, error) {
		gcpConfig, ok := authConfig.(GCPAuthConfig)
		if !ok {
			return nil, errors.New("invalid auth config type for GCP verifier")
		}
		return NewGCPVerifier(ctx, logger, gcpConfig)
	}
}

// NewGCPVerifier creates a new GCP verifier.
//
// Identity federation mode (IDTokenFile + Audience + GlobalRoleARN set):
//
//	JWT → AWS AssumeRoleWithWebIdentity(GlobalRoleARN) → AWS creds →
//	GCP STS(Audience) → Service Account Impersonation
//
// Default credentials mode (testing): Application Default Credentials.
func NewGCPVerifier(ctx context.Context, logger *zap.Logger, authConfig GCPAuthConfig) (*GCPVerifier, error) {
	httpClient := newHTTPClient()
	var opts []option.ClientOption

	switch {
	case authConfig.IsIdentityFederation():
		// AWS-mediated WIF flow:
		// 1. Assume Elastic global AWS role using the OIDC JWT (via FIPS HTTP client)
		// 2. Supply AWS credentials to GCP STS for WIF token exchange (via FIPS HTTP client)
		// 3. Impersonate the target GCP service account
		tokenSource, err := libbeatgcp.NewTokenSource(ctx, libbeatgcp.Params{
			Audience:            authConfig.Audience,
			GlobalRoleARN:       authConfig.GlobalRoleARN,
			JWTFilePath:         authConfig.IDTokenFile,
			SessionName:         authConfig.CloudResourceID + "-" + authConfig.IdentityFederationID,
			ServiceAccountEmail: authConfig.ServiceAccountEmail,
			HTTPClient:          httpClient,
		})
		if err != nil {
			logger.Warn("Failed to create GCP external account token source", zap.Error(err))
			httpClient.CloseIdleConnections()
			return &GCPVerifier{logger: logger, configured: false}, nil
		}
		// oauth2.NewClient wraps the FIPS client from httpClient with oauth2.Transport,
		// attaching the Bearer token to every GCP API request while keeping TLS FIPS-compliant.
		// Note: option.WithHTTPClient bypasses credential injection when used alongside
		// option.WithTokenSource, so we use a single pre-wrapped client.
		ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		opts = append(opts, option.WithHTTPClient(oauth2.NewClient(ctxWithClient, tokenSource)))
		logger.Info("GCP identity federation AWS-mediated WIF credential configured",
			zap.String("audience", authConfig.Audience),
			zap.String("global_role", authConfig.GlobalRoleARN),
			zap.Bool("has_service_account_impersonation", authConfig.ServiceAccountEmail != ""),
		)

	case authConfig.UseDefaultCredentials:
		logger.Info("Configuring GCP default credentials (testing)")
		// Inject the FIPS HTTP client so credential discovery uses FIPS-compliant TLS.
		ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		creds, err := google.FindDefaultCredentials(ctxWithClient,
			"https://www.googleapis.com/auth/cloud-platform.read-only",
		)
		if err != nil {
			logger.Warn("Failed to find GCP default credentials", zap.Error(err))
			httpClient.CloseIdleConnections()
			return &GCPVerifier{logger: logger, configured: false}, nil
		}
		// option.WithHTTPClient bypasses credential injection, so pass only
		// the credentials here. The FIPS HTTP client was injected into the ADC
		// discovery path via the context above.
		opts = append(opts, option.WithCredentials(creds))
		if authConfig.ProjectID == "" && creds.ProjectID != "" {
			authConfig.ProjectID = creds.ProjectID
		}

	default:
		logger.Warn("GCP credentials not fully configured")
		httpClient.CloseIdleConnections()
		return &GCPVerifier{logger: logger, configured: false}, nil
	}

	// Fall back to well-known environment variables when no project ID was derived
	// from the config (e.g., testing with Application Default Credentials that
	// don't embed a project).
	if authConfig.ProjectID == "" {
		if p := os.Getenv("GOOGLE_CLOUD_PROJECT"); p != "" {
			authConfig.ProjectID = p
		} else if p := os.Getenv("GCLOUD_PROJECT"); p != "" {
			authConfig.ProjectID = p
		}
	}

	logger.Info("GCP credential configured successfully",
		zap.String("project_id", authConfig.ProjectID),
	)

	return &GCPVerifier{
		logger:              logger,
		opts:                opts,
		httpClient:          httpClient,
		configured:          true,
		authConfig:          authConfig,
		projectID:           authConfig.ProjectID,
		serviceAccountEmail: authConfig.ServiceAccountEmail,
	}, nil
}

func (v *GCPVerifier) ProviderType() ProviderType {
	return ProviderGCP
}

func (v *GCPVerifier) Close() error {
	if v.httpClient != nil {
		v.httpClient.CloseIdleConnections()
	}
	return nil
}

// Verify checks if a GCP permission is granted using testIamPermissions.
// For CSPM and asset inventory integrations, IAM role binding is verified
// instead via cloudresourcemanager:GetIamPolicy.
func (v *GCPVerifier) Verify(ctx context.Context, permission Permission, providerCfg ProviderConfig) Result {
	start := time.Now()

	if !v.configured {
		return Result{
			Status:       StatusError,
			ErrorCode:    "ConfigurationError",
			ErrorMessage: "GCP credentials not configured",
			Duration:     time.Since(start),
		}
	}

	projectID := v.projectID
	if providerCfg.ProjectID != "" {
		projectID = providerCfg.ProjectID
	}

	v.logger.Debug("Verifying GCP permission",
		zap.String("action", permission.Action),
		zap.String("project_id", projectID),
		zap.String("method", string(permission.Method)),
	)

	var result Result
	if permission.Method == MethodPolicyAttachmentCheck {
		result = v.verifyPolicyAttachment(ctx, projectID, permission.Action)
	} else {
		result = v.testIAMPermissions(ctx, projectID, permission.Action)
	}

	result.Duration = time.Since(start)
	return result
}

// testIAMPermissions checks whether the authenticated principal has the given
// GCP IAM permission using the Cloud Resource Manager testIamPermissions API.
// This is the authoritative permission check: it evaluates all applicable IAM
// policies at the project level (including inherited organization/folder bindings)
// without making any data-plane API calls.
func (v *GCPVerifier) testIAMPermissions(ctx context.Context, projectID, action string) Result {
	svc, err := cloudresourcemanager.NewService(ctx, v.opts...)
	if err != nil {
		return v.handleGCPError(err, "cloudresourcemanager:NewService")
	}

	resp, err := svc.Projects.TestIamPermissions("projects/"+projectID,
		&cloudresourcemanager.TestIamPermissionsRequest{
			Permissions: []string{action},
		},
	).Context(ctx).Do()
	if err != nil {
		return v.handleGCPError(err, "cloudresourcemanager:TestIamPermissions")
	}

	for _, granted := range resp.Permissions {
		if granted == action {
			return Result{
				Status:   StatusGranted,
				Endpoint: "cloudresourcemanager:TestIamPermissions",
			}
		}
	}
	return Result{
		Status:       StatusDenied,
		ErrorCode:    "PermissionNotGranted",
		ErrorMessage: fmt.Sprintf("permission %s is not granted on project %s", action, projectID),
		Endpoint:     "cloudresourcemanager:TestIamPermissions",
	}
}

// verifyPolicyAttachment checks whether the expected IAM role is bound to the
// service account in the project's IAM policy.
//
// This method is used for CSPM and asset inventory integrations that require
// specific IAM role bindings rather than individual permissions.
func (v *GCPVerifier) verifyPolicyAttachment(ctx context.Context, projectID, expectedRole string) Result {
	svc, err := cloudresourcemanager.NewService(ctx, v.opts...)
	if err != nil {
		return v.handleGCPError(err, "cloudresourcemanager:NewService")
	}

	policy, err := svc.Projects.GetIamPolicy("projects/"+projectID,
		&cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return v.handleGCPError(err, "cloudresourcemanager:GetIamPolicy")
	}

	saEmail := v.serviceAccountEmail
	memberPrefix := "serviceAccount:" + saEmail

	for _, binding := range policy.Bindings {
		if binding.Role != expectedRole {
			continue
		}
		for _, member := range binding.Members {
			if member == memberPrefix {
				return Result{
					Status:   StatusGranted,
					Endpoint: fmt.Sprintf("cloudresourcemanager:GetIamPolicy (found %s bound to %s in project %s)", expectedRole, saEmail, projectID),
				}
			}
		}
	}

	return Result{
		Status:       StatusDenied,
		ErrorCode:    "RoleNotBound",
		ErrorMessage: fmt.Sprintf("IAM role %s is not bound to %s in project %s", expectedRole, saEmail, projectID),
		Endpoint:     "cloudresourcemanager:GetIamPolicy",
	}
}

// handleGCPError converts a GCP API error to a verification result.
func (v *GCPVerifier) handleGCPError(err error, endpoint string) Result {
	if err == nil {
		return Result{
			Status:   StatusGranted,
			Endpoint: endpoint,
		}
	}

	var gErr *googleapi.Error
	if errors.As(err, &gErr) {
		if gErr.Code == 401 || gErr.Code == 403 {
			return Result{
				Status:       StatusDenied,
				ErrorCode:    fmt.Sprintf("HTTP_%d", gErr.Code),
				ErrorMessage: gErr.Message,
				Endpoint:     endpoint,
			}
		}
		return Result{
			Status:       StatusError,
			ErrorCode:    fmt.Sprintf("HTTP_%d", gErr.Code),
			ErrorMessage: gErr.Message,
			Endpoint:     endpoint,
		}
	}

	var tokenErr *oauth2.RetrieveError
	if errors.As(err, &tokenErr) {
		if tokenErr.Response != nil && (tokenErr.Response.StatusCode == 401 || tokenErr.Response.StatusCode == 403) {
			return Result{
				Status:       StatusDenied,
				ErrorCode:    "AuthenticationFailed",
				ErrorMessage: err.Error(),
				Endpoint:     endpoint,
			}
		}
		return Result{
			Status:       StatusError,
			ErrorCode:    "TokenRetrievalError",
			ErrorMessage: err.Error(),
			Endpoint:     endpoint,
		}
	}

	return Result{
		Status:       StatusError,
		ErrorMessage: err.Error(),
		Endpoint:     endpoint,
	}
}

