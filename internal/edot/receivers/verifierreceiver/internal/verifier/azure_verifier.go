// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"go.uber.org/zap"
)

// AzureVerifier implements permission verification for Azure.
type AzureVerifier struct {
	logger        *zap.Logger
	credential    azcore.TokenCredential
	httpClient    *http.Client // TLS 1.3 — used for Entra ID (login.microsoftonline.com)
	armHTTPClient *http.Client // TLS 1.2 — used for ARM (management.azure.com, TLS 1.3 unconfirmed)
	configured    bool
	authConfig    AzureAuthConfig

	cachedSubscriptionID string
	subscriptionOnce     sync.Once
	subscriptionErr      error

	// cachedPermissions holds the effective permissions (actions) for the
	// authenticated principal at subscription scope, loaded once per session.
	cachedPermissions    []string
	cachedNotPermissions []string
	permissionsOnce      sync.Once
	permissionsErr       error
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
// Identity federation mode (IDTokenFile set):
//
//	JWT → ClientAssertionCredential(TenantID, ClientID) → Azure Token
//
// Default credentials mode (testing): DefaultAzureCredential (az login).
func NewAzureVerifier(ctx context.Context, logger *zap.Logger, authConfig AzureAuthConfig) (*AzureVerifier, error) {
	// TLS 1.3 for Entra ID (login.microsoftonline.com — confirmed TLS 1.3 support).
	httpClient := newHTTPClient()
	// TLS 1.2 for ARM (management.azure.com — TLS 1.3 not yet officially confirmed).
	armHTTPClient := newTLS12HTTPClient()
	clientOpts := azcore.ClientOptions{Transport: httpClient}

	closeAll := func() {
		httpClient.CloseIdleConnections()
		armHTTPClient.CloseIdleConnections()
	}

	var cred azcore.TokenCredential
	var err error

	switch {
	case authConfig.IsIdentityFederation():
		// Identity federation OIDC flow: use the JWT as a federated client assertion.
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
			&azidentity.ClientAssertionCredentialOptions{ClientOptions: clientOpts},
		)
		if err != nil {
			logger.Warn("Failed to create Azure client assertion credential", zap.Error(err))
			closeAll()
			return &AzureVerifier{logger: logger, configured: false}, nil
		}
		logger.Info("Azure identity federation credential configured (ClientAssertion)")

	case authConfig.UseDefaultCredentials:
		cred, err = azidentity.NewDefaultAzureCredential(
			&azidentity.DefaultAzureCredentialOptions{ClientOptions: clientOpts},
		)
		if err != nil {
			logger.Warn("Failed to create Azure default credential", zap.Error(err))
			closeAll()
			return &AzureVerifier{logger: logger, configured: false}, nil
		}
		logger.Info("Azure default credential configured (testing, uses az login / env vars)")

	default:
		logger.Warn("Azure credentials not fully configured")
		closeAll()
		return &AzureVerifier{logger: logger, configured: false}, nil
	}

	return &AzureVerifier{
		logger:        logger,
		credential:    cred,
		httpClient:    httpClient,
		armHTTPClient: armHTTPClient,
		configured:    true,
		authConfig:    authConfig,
	}, nil
}

// armClientOptions returns [*arm.ClientOptions] that routes all ARM API calls
// through the TLS 1.2 HTTP client (management.azure.com, TLS 1.3 unconfirmed).
func (v *AzureVerifier) armClientOptions() *arm.ClientOptions {
	return &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: v.armHTTPClient},
	}
}

func (v *AzureVerifier) ProviderType() ProviderType {
	return ProviderAzure
}

func (v *AzureVerifier) Close() error {
	if v.httpClient != nil {
		v.httpClient.CloseIdleConnections()
	}
	if v.armHTTPClient != nil {
		v.armHTTPClient.CloseIdleConnections()
	}
	return nil
}

// discoverSubscriptionID discovers the subscription ID at runtime by listing
// the subscriptions visible to the authenticated principal. The result is
// cached after the first successful call.
func (v *AzureVerifier) discoverSubscriptionID(ctx context.Context) (string, error) {
	v.subscriptionOnce.Do(func() {
		client, err := armsubscriptions.NewClient(v.credential, v.armClientOptions())
		if err != nil {
			v.subscriptionErr = fmt.Errorf("creating subscriptions client: %w", err)
			return
		}
		pager := client.NewListPager(nil)
		page, err := pager.NextPage(ctx)
		if err != nil {
			v.subscriptionErr = fmt.Errorf("listing subscriptions: %w", err)
			return
		}
		if len(page.Value) == 0 {
			v.subscriptionErr = errors.New("no subscriptions found for the authenticated principal")
			return
		}
		v.cachedSubscriptionID = *page.Value[0].SubscriptionID
		v.logger.Info("Discovered Azure subscription",
			zap.String("subscription_id", v.cachedSubscriptionID),
		)
	})
	return v.cachedSubscriptionID, v.subscriptionErr
}

// azurePermissionsResponse is the shape of the ARM
// /subscriptions/{id}/providers/Microsoft.Authorization/permissions response.
type azurePermissionsResponse struct {
	Value []struct {
		Actions    []string `json:"actions"`
		NotActions []string `json:"notActions"`
	} `json:"value"`
	NextLink *string `json:"nextLink"`
}

// loadPermissions fetches and caches the effective permissions for the
// authenticated principal at the subscription scope. It calls the ARM
// permissions endpoint directly:
//
//	GET /subscriptions/{id}/providers/Microsoft.Authorization/permissions
//
// The result is cached for the lifetime of the verifier instance.
func (v *AzureVerifier) loadPermissions(ctx context.Context, subscriptionID string) error {
	v.permissionsOnce.Do(func() {
		v.permissionsErr = v.doLoadPermissions(ctx, subscriptionID)
		if v.permissionsErr == nil {
			v.logger.Info("Loaded Azure effective permissions",
				zap.Int("actions", len(v.cachedPermissions)),
				zap.Int("not_actions", len(v.cachedNotPermissions)),
			)
		}
	})
	return v.permissionsErr
}

func (v *AzureVerifier) doLoadPermissions(ctx context.Context, subscriptionID string) error {
	token, err := v.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return fmt.Errorf("getting ARM bearer token: %w", err)
	}

	nextURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/permissions?api-version=2022-04-01",
		subscriptionID,
	)

	for nextURL != "" {
		page, err := v.fetchPermissionsPage(ctx, nextURL, token.Token)
		if err != nil {
			return err
		}
		for _, perm := range page.Value {
			v.cachedPermissions = append(v.cachedPermissions, perm.Actions...)
			v.cachedNotPermissions = append(v.cachedNotPermissions, perm.NotActions...)
		}
		if page.NextLink != nil && *page.NextLink != "" {
			nextURL = *page.NextLink
		} else {
			nextURL = ""
		}
	}
	return nil
}

func (v *AzureVerifier) fetchPermissionsPage(ctx context.Context, url, bearerToken string) (azurePermissionsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return azurePermissionsResponse{}, fmt.Errorf("creating permissions request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/json")

	resp, err := v.armHTTPClient.Do(req)
	if err != nil {
		return azurePermissionsResponse{}, fmt.Errorf("calling ARM permissions API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return azurePermissionsResponse{}, fmt.Errorf("ARM permissions API returned HTTP %d", resp.StatusCode)
	}

	var result azurePermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return azurePermissionsResponse{}, fmt.Errorf("decoding permissions response: %w", err)
	}
	return result, nil
}

// checkPermission returns true if the given Azure action is covered by the
// cached permissions (considering wildcards) and not excluded by notActions.
func (v *AzureVerifier) checkPermission(action string) bool {
	granted := false
	for _, perm := range v.cachedPermissions {
		if matchAzurePermission(perm, action) {
			granted = true
			break
		}
	}
	if !granted {
		return false
	}
	for _, notPerm := range v.cachedNotPermissions {
		if matchAzurePermission(notPerm, action) {
			return false
		}
	}
	return true
}

// matchAzurePermission reports whether the Azure RBAC permission pattern
// matches the given action. Both are compared case-insensitively.
// Supported wildcard forms: "*", "Microsoft.Compute/*", "Microsoft.Compute/virtualMachines/*".
func matchAzurePermission(pattern, action string) bool {
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)
	if pattern == action || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(action, prefix+"/")
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(action, prefix)
	}
	return false
}

// Verify checks if an Azure permission is granted by comparing the action
// against the principal's effective permissions at subscription scope.
// For CSPM and asset inventory integrations, RBAC role assignment is verified
// instead via armauthorization:ListRoleAssignments.
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

	subscriptionID, err := v.discoverSubscriptionID(ctx)
	if err != nil {
		return Result{
			Status:       StatusError,
			ErrorCode:    "SubscriptionDiscoveryError",
			ErrorMessage: fmt.Sprintf("failed to discover Azure subscription: %v", err),
			Duration:     time.Since(start),
		}
	}

	v.logger.Debug("Verifying Azure permission",
		zap.String("action", permission.Action),
		zap.String("subscription_id", subscriptionID),
		zap.String("method", string(permission.Method)),
	)

	var result Result
	if permission.Method == MethodPolicyAttachmentCheck {
		result = v.verifyPolicyAttachment(ctx, subscriptionID, permission.Action)
	} else {
		result = v.verifyViaPermissionsList(ctx, subscriptionID, permission.Action)
	}

	result.Duration = time.Since(start)
	return result
}

// verifyViaPermissionsList checks whether the action is present in the
// principal's effective subscription-scope permissions loaded from the ARM
// permissions API. This is the authoritative permission check: it evaluates
// the effective RBAC result without making any data-plane API calls.
func (v *AzureVerifier) verifyViaPermissionsList(ctx context.Context, subscriptionID, action string) Result {
	if err := v.loadPermissions(ctx, subscriptionID); err != nil {
		return Result{
			Status:       StatusError,
			ErrorCode:    "PermissionsLoadError",
			ErrorMessage: fmt.Sprintf("failed to load Azure permissions: %v", err),
			Endpoint:     "Microsoft.Authorization/permissions",
		}
	}

	if v.checkPermission(action) {
		return Result{
			Status:   StatusGranted,
			Endpoint: "Microsoft.Authorization/permissions",
		}
	}
	return Result{
		Status:       StatusDenied,
		ErrorCode:    "PermissionNotGranted",
		ErrorMessage: fmt.Sprintf("action %s is not in the principal's effective permissions at subscription scope", action),
		Endpoint:     "Microsoft.Authorization/permissions",
	}
}

// verifyPolicyAttachment checks whether the authenticated principal has a
// specific built-in role assigned at the subscription scope.
// The action string is the role name (e.g. "Reader") and the role definition
// GUID is embedded in the method for known roles.
//
// This method is used for CSPM and asset inventory integrations that require
// specific RBAC role assignments rather than individual action permissions.
func (v *AzureVerifier) verifyPolicyAttachment(ctx context.Context, subscriptionID, roleName string) Result {
	roleGUID := resolveAzureRoleGUID(roleName)
	if roleGUID == "" {
		return Result{
			Status:       StatusError,
			ErrorCode:    "UnknownRole",
			ErrorMessage: "no known GUID for Azure role: " + roleName,
			Endpoint:     "armauthorization:ListRoleAssignments",
		}
	}

	expectedRoleDefSuffix := "/providers/Microsoft.Authorization/roleDefinitions/" + roleGUID

	client, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, v.credential, v.armClientOptions())
	if err != nil {
		return v.handleAzureError(err, "armauthorization:NewRoleAssignmentsClient")
	}

	scope := "/subscriptions/" + subscriptionID
	pager := client.NewListForScopePager(scope, nil)
	for pager.More() {
		page, pageErr := pager.NextPage(ctx)
		if pageErr != nil {
			return v.handleAzureError(pageErr, "armauthorization:ListForScope")
		}
		for _, assignment := range page.Value {
			if assignment.Properties != nil && assignment.Properties.RoleDefinitionID != nil {
				if strings.HasSuffix(*assignment.Properties.RoleDefinitionID, expectedRoleDefSuffix) {
					return Result{
						Status:   StatusGranted,
						Endpoint: fmt.Sprintf("armauthorization:ListForScope (found %s role on subscription %s)", roleName, subscriptionID),
					}
				}
			}
		}
	}

	return Result{
		Status:       StatusDenied,
		ErrorCode:    "RoleNotAssigned",
		ErrorMessage: fmt.Sprintf("built-in role %s (GUID %s) is not assigned on subscription %s", roleName, roleGUID, subscriptionID),
		Endpoint:     "armauthorization:ListForScope",
	}
}

// resolveAzureRoleGUID returns the well-known GUID for an Azure built-in role name.
func resolveAzureRoleGUID(roleName string) string {
	switch roleName {
	case "Reader":
		return "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	default:
		return ""
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
