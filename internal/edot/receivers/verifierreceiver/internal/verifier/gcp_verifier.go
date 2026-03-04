// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	cloudasset "google.golang.org/api/cloudasset/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
	pubsubapi "google.golang.org/api/pubsub/v1"
	storageapi "google.golang.org/api/storage/v1"

	"golang.org/x/oauth2/google"
)

// GCPVerifier implements permission verification for GCP.
type GCPVerifier struct {
	logger     *zap.Logger
	opts       []option.ClientOption
	configured bool
	authConfig GCPAuthConfig
	projectID  string
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
// Cloud connector mode (IDTokenFile + WorkloadIdentityProvider set):
//
//	JWT → GCP Workload Identity Federation(audience) → Service Account Impersonation
//
// Default credentials mode (testing): Application Default Credentials.
func NewGCPVerifier(ctx context.Context, logger *zap.Logger, authConfig GCPAuthConfig) (*GCPVerifier, error) {
	var opts []option.ClientOption

	switch {
	case authConfig.IsCloudConnector():
		// Cloud connector WIF flow: build an external_account credential config
		// that reads the OIDC JWT from a file and exchanges it for a GCP token
		// via the STS endpoint.
		extAccount := map[string]interface{}{
			"type":               "external_account",
			"audience":           authConfig.WorkloadIdentityProvider,
			"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"token_url":          "https://sts.googleapis.com/v1/token",
			"credential_source": map[string]interface{}{
				"file": authConfig.IDTokenFile,
				"format": map[string]interface{}{
					"type": "text",
				},
			},
		}
		if authConfig.ServiceAccountEmail != "" {
			extAccount["service_account_impersonation_url"] = fmt.Sprintf(
				"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
				authConfig.ServiceAccountEmail,
			)
		}

		credJSON, err := json.Marshal(extAccount)
		if err != nil {
			return nil, fmt.Errorf("failed to build GCP WIF credential config: %w", err)
		}

		creds, err := google.CredentialsFromJSON(ctx, credJSON,
			"https://www.googleapis.com/auth/cloud-platform.read-only",
		)
		if err != nil {
			logger.Warn("Failed to create GCP WIF credentials", zap.Error(err))
			return &GCPVerifier{logger: logger, configured: false}, nil
		}
		opts = append(opts, option.WithCredentials(creds))
		logger.Info("GCP cloud connector WIF credential configured",
			zap.String("audience", authConfig.WorkloadIdentityProvider),
			zap.Bool("has_service_account_impersonation", authConfig.ServiceAccountEmail != ""),
		)

	case authConfig.UseDefaultCredentials:
		logger.Info("Configuring GCP default credentials (testing)")
		creds, err := google.FindDefaultCredentials(ctx,
			"https://www.googleapis.com/auth/cloud-platform.read-only",
		)
		if err != nil {
			logger.Warn("Failed to find GCP default credentials", zap.Error(err))
			return &GCPVerifier{logger: logger, configured: false}, nil
		}
		opts = append(opts, option.WithCredentials(creds))
		if authConfig.ProjectID == "" && creds.ProjectID != "" {
			authConfig.ProjectID = creds.ProjectID
		}

	default:
		logger.Warn("GCP credentials not fully configured")
		return &GCPVerifier{logger: logger, configured: false}, nil
	}

	logger.Info("GCP credential configured successfully",
		zap.String("project_id", authConfig.ProjectID),
	)

	return &GCPVerifier{
		logger:     logger,
		opts:       opts,
		configured: true,
		authConfig: authConfig,
		projectID:  authConfig.ProjectID,
	}, nil
}

func (v *GCPVerifier) ProviderType() ProviderType {
	return ProviderGCP
}

func (v *GCPVerifier) Close() error {
	return nil
}

// Verify checks if a GCP permission is granted by making a minimal API call.
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

	// GCP permissions look like "service.resource.verb" (e.g. "compute.instances.list").
	service := extractGCPService(permission.Action)

	v.logger.Debug("Verifying GCP permission",
		zap.String("service", service),
		zap.String("action", permission.Action),
		zap.String("project_id", projectID),
	)

	var result Result
	switch service {
	case "resourcemanager":
		result = v.verifyResourceManager(ctx, projectID, permission.Action)
	case "cloudasset":
		result = v.verifyCloudAsset(ctx, projectID, permission.Action)
	case "logging":
		result = v.verifyLogging(ctx, projectID, permission.Action)
	case "storage":
		result = v.verifyStorage(ctx, projectID, permission.Action)
	case "pubsub":
		result = v.verifyPubSub(ctx, projectID, permission.Action)
	case "compute":
		result = v.verifyCompute(ctx, projectID, permission.Action)
	default:
		result = Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported GCP service: " + service,
		}
	}

	result.Duration = time.Since(start)
	return result
}

// extractGCPService returns the service prefix from a GCP permission string
// (e.g. "compute" from "compute.instances.list").
func extractGCPService(action string) string {
	parts := strings.SplitN(action, ".", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func (v *GCPVerifier) verifyResourceManager(ctx context.Context, projectID, action string) Result {
	switch {
	case strings.Contains(action, "projects.get"):
		svc, err := cloudresourcemanager.NewService(ctx, v.opts...)
		if err != nil {
			return v.handleGCPError(err, action)
		}
		_, err = svc.Projects.Get("projects/" + projectID).Context(ctx).Do()
		return v.handleGCPError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Resource Manager action: " + action,
		}
	}
}

func (v *GCPVerifier) verifyCloudAsset(ctx context.Context, projectID, action string) Result {
	switch {
	case strings.Contains(action, "searchAllResources"):
		svc, err := cloudasset.NewService(ctx, v.opts...)
		if err != nil {
			return v.handleGCPError(err, action)
		}
		_, err = svc.V1.SearchAllResources("projects/" + projectID).PageSize(1).Context(ctx).Do()
		return v.handleGCPError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Cloud Asset action: " + action,
		}
	}
}

func (v *GCPVerifier) verifyLogging(ctx context.Context, projectID, action string) Result {
	switch {
	case strings.Contains(action, "logEntries.list"):
		svc, err := logging.NewService(ctx, v.opts...)
		if err != nil {
			return v.handleGCPError(err, action)
		}
		_, err = svc.Entries.List(&logging.ListLogEntriesRequest{
			ResourceNames: []string{"projects/" + projectID},
			PageSize:      1,
		}).Context(ctx).Do()
		return v.handleGCPError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Logging action: " + action,
		}
	}
}

func (v *GCPVerifier) verifyStorage(ctx context.Context, projectID, action string) Result {
	switch {
	case strings.Contains(action, "buckets.list"):
		svc, err := storageapi.NewService(ctx, v.opts...)
		if err != nil {
			return v.handleGCPError(err, action)
		}
		_, err = svc.Buckets.List(projectID).MaxResults(1).Context(ctx).Do()
		return v.handleGCPError(err, action)

	case strings.Contains(action, "objects.get") || strings.Contains(action, "objects.list"):
		svc, err := storageapi.NewService(ctx, v.opts...)
		if err != nil {
			return v.handleGCPError(err, action)
		}
		_, err = svc.Buckets.List(projectID).MaxResults(1).Context(ctx).Do()
		if err != nil {
			return v.handleGCPError(err, action)
		}
		return Result{
			Status:   StatusGranted,
			Endpoint: action + " (verified via buckets.list)",
		}

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Storage action: " + action,
		}
	}
}

func (v *GCPVerifier) verifyPubSub(ctx context.Context, projectID, action string) Result {
	switch {
	case strings.Contains(action, "subscriptions.consume"):
		svc, err := pubsubapi.NewService(ctx, v.opts...)
		if err != nil {
			return v.handleGCPError(err, action)
		}
		_, err = svc.Projects.Subscriptions.List("projects/" + projectID).Context(ctx).Do()
		if err != nil {
			return v.handleGCPError(err, action)
		}
		return Result{
			Status:   StatusGranted,
			Endpoint: action + " (verified via subscriptions.list)",
		}

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Pub/Sub action: " + action,
		}
	}
}

func (v *GCPVerifier) verifyCompute(ctx context.Context, projectID, action string) Result {
	switch {
	case strings.Contains(action, "instances.list"):
		svc, err := compute.NewService(ctx, v.opts...)
		if err != nil {
			return v.handleGCPError(err, action)
		}
		// List instances in a single zone is not required; use aggregated list.
		_, err = svc.Instances.AggregatedList(projectID).MaxResults(1).Context(ctx).Do()
		return v.handleGCPError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Compute action: " + action,
		}
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
