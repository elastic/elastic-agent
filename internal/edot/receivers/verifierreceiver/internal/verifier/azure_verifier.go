// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"go.uber.org/zap"
)

// AzureVerifier implements permission verification for Azure.
type AzureVerifier struct {
	logger         *zap.Logger
	credential     azcore.TokenCredential
	configured     bool
	authConfig     AzureAuthConfig
	subscriptionID string
}

var _ Verifier = (*AzureVerifier)(nil)

// NewAzureVerifierFactory returns a factory function for creating Azure verifiers.
func NewAzureVerifierFactory() VerifierFactory {
	return func(ctx context.Context, logger *zap.Logger, authConfig AuthConfig) (Verifier, error) {
		azureConfig, ok := authConfig.(AzureAuthConfig)
		if !ok {
			return nil, errors.New("invalid auth config type for Azure verifier")
		}
		return NewAzureVerifier(ctx, logger, azureConfig)
	}
}

// NewAzureVerifier creates a new Azure verifier.
//
// Cloud connector mode (IDTokenFile set):
//
//	JWT → ClientAssertionCredential(TenantID, ClientID) → Azure Token
//
// Default credentials mode (testing): DefaultAzureCredential (az login).
func NewAzureVerifier(ctx context.Context, logger *zap.Logger, authConfig AzureAuthConfig) (*AzureVerifier, error) {
	var cred azcore.TokenCredential
	var err error

	switch {
	case authConfig.IsCloudConnector():
		// Cloud connector OIDC flow: use the JWT as a federated client assertion.
		// The callback re-reads the file on each invocation so refreshed tokens
		// are picked up automatically.
		idTokenFile := authConfig.IDTokenFile
		getAssertion := func(_ context.Context) (string, error) {
			token, readErr := os.ReadFile(idTokenFile)
			if readErr != nil {
				return "", readErr
			}
			return strings.TrimSpace(string(token)), nil
		}

		cred, err = azidentity.NewClientAssertionCredential(
			authConfig.TenantID,
			authConfig.ClientID,
			getAssertion,
			nil,
		)
		if err != nil {
			logger.Warn("Failed to create Azure client assertion credential", zap.Error(err))
			return &AzureVerifier{logger: logger, configured: false}, nil
		}
		logger.Info("Azure cloud connector credential configured (ClientAssertion)")

	case authConfig.UseDefaultCredentials:
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			logger.Warn("Failed to create Azure default credential", zap.Error(err))
			return &AzureVerifier{logger: logger, configured: false}, nil
		}
		logger.Info("Azure default credential configured (testing, uses az login / env vars)")

	default:
		logger.Warn("Azure credentials not fully configured")
		return &AzureVerifier{logger: logger, configured: false}, nil
	}

	return &AzureVerifier{
		logger:         logger,
		credential:     cred,
		configured:     true,
		authConfig:     authConfig,
		subscriptionID: authConfig.SubscriptionID,
	}, nil
}

func (v *AzureVerifier) ProviderType() ProviderType {
	return ProviderAzure
}

func (v *AzureVerifier) Close() error {
	return nil
}

// Verify checks if an Azure permission is granted by making a minimal API call
// for the corresponding Azure resource provider.
func (v *AzureVerifier) Verify(ctx context.Context, permission Permission, providerCfg ProviderConfig) Result {
	start := time.Now()

	if !v.configured {
		return Result{
			Status:       StatusError,
			ErrorCode:    "ConfigurationError",
			ErrorMessage: "Azure credentials not configured",
			Duration:     time.Since(start),
		}
	}

	subscriptionID := v.subscriptionID
	if providerCfg.SubscriptionID != "" {
		subscriptionID = providerCfg.SubscriptionID
	}

	// Parse the action to determine the resource provider.
	// Azure actions look like "Microsoft.Compute/virtualMachines/read".
	service := extractAzureService(permission.Action)

	v.logger.Debug("Verifying Azure permission",
		zap.String("service", service),
		zap.String("action", permission.Action),
		zap.String("subscription_id", subscriptionID),
	)

	var result Result
	switch service {
	case "Microsoft.Resources":
		result = v.verifyResources(ctx, subscriptionID, permission.Action)
	case "Microsoft.Compute":
		result = v.verifyCompute(ctx, subscriptionID, permission.Action)
	case "Microsoft.Storage":
		result = v.verifyStorage(ctx, subscriptionID, permission.Action)
	case "Microsoft.Insights":
		result = v.verifyInsights(ctx, subscriptionID, permission.Action)
	case "Microsoft.Web":
		result = v.verifyWeb(ctx, subscriptionID, permission.Action)
	case "Microsoft.Network":
		result = v.verifyNetwork(ctx, subscriptionID, permission.Action)
	default:
		result = Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Azure service: " + service,
		}
	}

	result.Duration = time.Since(start)
	return result
}

// extractAzureService returns the top-level resource provider from an Azure
// action string (e.g. "Microsoft.Compute" from "Microsoft.Compute/virtualMachines/read").
func extractAzureService(action string) string {
	parts := strings.SplitN(action, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func (v *AzureVerifier) verifyResources(ctx context.Context, subscriptionID, action string) Result {
	switch {
	case strings.Contains(action, "subscriptions/resources/read"):
		client, err := armresources.NewClient(subscriptionID, v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		pager := client.NewListPager(nil)
		// Fetch only the first page to verify access.
		_, err = pager.NextPage(ctx)
		return v.handleAzureError(err, action)

	case strings.Contains(action, "subscriptions/read"):
		client, err := armsubscriptions.NewClient(v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		pager := client.NewListPager(nil)
		_, err = pager.NextPage(ctx)
		return v.handleAzureError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Resources action: " + action,
		}
	}
}

func (v *AzureVerifier) verifyCompute(ctx context.Context, subscriptionID, action string) Result {
	switch {
	case strings.Contains(action, "virtualMachines/read"):
		client, err := armcompute.NewVirtualMachinesClient(subscriptionID, v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		pager := client.NewListAllPager(nil)
		_, err = pager.NextPage(ctx)
		return v.handleAzureError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Compute action: " + action,
		}
	}
}

func (v *AzureVerifier) verifyStorage(ctx context.Context, subscriptionID, action string) Result {
	switch {
	case strings.Contains(action, "storageAccounts/read"):
		client, err := armstorage.NewAccountsClient(subscriptionID, v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		pager := client.NewListPager(nil)
		_, err = pager.NextPage(ctx)
		return v.handleAzureError(err, action)

	case strings.Contains(action, "blobServices/containers/read"):
		// Listing blob containers requires a storage account name. Fall back to
		// listing storage accounts as a proxy check.
		client, err := armstorage.NewAccountsClient(subscriptionID, v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		pager := client.NewListPager(nil)
		_, err = pager.NextPage(ctx)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		return Result{
			Status:   StatusGranted,
			Endpoint: action + " (verified via storageAccounts list)",
		}

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Storage action: " + action,
		}
	}
}

func (v *AzureVerifier) verifyInsights(ctx context.Context, subscriptionID, action string) Result {
	switch {
	case strings.Contains(action, "eventtypes/values/Read"):
		client, err := armmonitor.NewActivityLogsClient(subscriptionID, v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		// Filter to the last hour to keep the response small.
		filter := "eventTimestamp ge '" + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + "'"
		pager := client.NewListPager(filter, nil)
		_, err = pager.NextPage(ctx)
		return v.handleAzureError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Insights action: " + action,
		}
	}
}

func (v *AzureVerifier) verifyWeb(ctx context.Context, subscriptionID, action string) Result {
	switch {
	case strings.Contains(action, "sites/config/Read") || strings.Contains(action, "sites/read") || strings.Contains(action, "sites/*/read"):
		client, err := armappservice.NewWebAppsClient(subscriptionID, v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		pager := client.NewListPager(nil)
		_, err = pager.NextPage(ctx)
		return v.handleAzureError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Web action: " + action,
		}
	}
}

func (v *AzureVerifier) verifyNetwork(ctx context.Context, subscriptionID, action string) Result {
	switch {
	case strings.Contains(action, "networkSecurityGroups/read"):
		client, err := armnetwork.NewSecurityGroupsClient(subscriptionID, v.credential, nil)
		if err != nil {
			return v.handleAzureError(err, action)
		}
		pager := client.NewListAllPager(nil)
		_, err = pager.NextPage(ctx)
		return v.handleAzureError(err, action)

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Network action: " + action,
		}
	}
}

// handleAzureError converts an Azure SDK error to a verification result.
func (v *AzureVerifier) handleAzureError(err error, endpoint string) Result {
	if err == nil {
		return Result{
			Status:   StatusGranted,
			Endpoint: endpoint,
		}
	}

	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		if isAzureAccessDeniedError(respErr.ErrorCode) || respErr.StatusCode == 401 || respErr.StatusCode == 403 {
			return Result{
				Status:       StatusDenied,
				ErrorCode:    respErr.ErrorCode,
				ErrorMessage: respErr.Error(),
				Endpoint:     endpoint,
			}
		}
		return Result{
			Status:       StatusError,
			ErrorCode:    respErr.ErrorCode,
			ErrorMessage: respErr.Error(),
			Endpoint:     endpoint,
		}
	}

	return Result{
		Status:       StatusError,
		ErrorMessage: err.Error(),
		Endpoint:     endpoint,
	}
}

func isAzureAccessDeniedError(code string) bool {
	deniedCodes := []string{
		"AuthorizationFailed",
		"AuthenticationFailed",
		"AuthenticationFailedInvalidHeader",
		"Forbidden",
		"AuthorizationPermissionMismatch",
		"LinkedAuthorizationFailed",
		"InvalidAuthenticationToken",
		"InvalidAuthenticationTokenTenant",
		"AccountIsDisabled",
		"InsufficientAccountPermissions",
	}
	for _, c := range deniedCodes {
		if code == c {
			return true
		}
	}
	return false
}
