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
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"go.uber.org/zap"
)

const (
	defaultSessionName        = "verifier-receiver"
	defaultAssumeRoleDuration = 15 * time.Minute
	// Used by the identity federation WebIdentity step. The global role session
	// is short-lived because it is only an intermediate step before assuming
	// the customer's role.
	defaultIntermediateDuration = 20 * time.Minute
)

// AWSVerifier implements permission verification for AWS.
type AWSVerifier struct {
	logger     *zap.Logger
	baseConfig aws.Config
	configured bool
	authConfig AWSAuthConfig
	httpClient *http.Client

	// cachedCallerARN caches the IAM role ARN returned by sts:GetCallerIdentity
	// for use as PolicySourceArn in iam:SimulatePrincipalPolicy calls.
	callerARNMu     sync.Mutex
	cachedCallerARN string
}

// Ensure AWSVerifier implements Verifier interface.
var _ Verifier = (*AWSVerifier)(nil)

// NewAWSVerifierFactory returns a factory function for creating AWS verifiers.
// This factory should be registered with the verifier Registry.
func NewAWSVerifierFactory() VerifierFactory {
	return func(ctx context.Context, logger *zap.Logger, authConfig AuthConfig) (Verifier, error) {
		awsConfig, ok := authConfig.(AWSAuthConfig)
		if !ok {
			return nil, errors.New("invalid auth config type for AWS verifier")
		}
		return NewAWSVerifier(ctx, logger, awsConfig)
	}
}

// NewAWSVerifier creates a new AWS verifier.
//
// Identity federation mode (IDTokenFile + GlobalRoleARN set):
//
//	JWT → WebIdentity(GlobalRoleARN) → AssumeRole(customer RoleARN, ExternalID)
//
// Default credentials mode (testing): uses the default AWS credential chain.
func NewAWSVerifier(ctx context.Context, logger *zap.Logger, authConfig AWSAuthConfig) (*AWSVerifier, error) {
	httpClient := newHTTPClient()

	baseCfg, err := config.LoadDefaultConfig(ctx,
		config.WithHTTPClient(httpClient),
	)
	if err != nil {
		logger.Warn("Failed to load default AWS config", zap.Error(err))
		httpClient.CloseIdleConnections()
		return &AWSVerifier{
			logger:     logger,
			configured: false,
		}, nil
	}

	sessionName := authConfig.SessionName
	if sessionName == "" {
		sessionName = defaultSessionName
	}

	duration := authConfig.AssumeRoleDuration
	if duration == 0 {
		duration = defaultAssumeRoleDuration
	}

	switch {
	case authConfig.IsIdentityFederation():
		if irsaTokenFile := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); irsaTokenFile != "" {
			// IRSA flow: LoadDefaultConfig already picked up the pod's service-account
			// token via AWS_WEB_IDENTITY_TOKEN_FILE, so baseCfg carries IRSA credentials.
			// Step 1: Assume the Elastic Global Role using those IRSA credentials.
			assumeGlobalRoleProvider := stscreds.NewAssumeRoleProvider(
				sts.NewFromConfig(baseCfg),
				authConfig.GlobalRoleARN,
				func(aro *stscreds.AssumeRoleOptions) {
					aro.Duration = defaultIntermediateDuration
				},
			)
			baseCfg.Credentials = aws.NewCredentialsCache(assumeGlobalRoleProvider)

			// Step 2: Assume the customer's role from the global role session.
			// ExternalID follows the Cloudbeat/Beats convention: ResourceID-ExternalID.
			assumeRoleProvider := stscreds.NewAssumeRoleProvider(
				sts.NewFromConfig(baseCfg),
				authConfig.RoleARN,
				func(aro *stscreds.AssumeRoleOptions) {
					aro.RoleSessionName = sessionName
					aro.Duration = duration
					if authConfig.CloudResourceID != "" && authConfig.ExternalID != "" {
						aro.ExternalID = aws.String(authConfig.CloudResourceID + "-" + authConfig.ExternalID)
					} else if authConfig.ExternalID != "" {
						aro.ExternalID = aws.String(authConfig.ExternalID)
					}
				},
			)
			baseCfg.Credentials = aws.NewCredentialsCache(assumeRoleProvider)

			logger.Info("AWS identity federation IRSA credential chain configured",
				zap.String("global_role", authConfig.GlobalRoleARN),
				zap.String("customer_role", authConfig.RoleARN),
			)
		} else {
			// OIDC flow: two-step credential chain using the JWT token file.
			// Step 1: Assume Elastic Global Role using the OIDC JWT token.
			webIdentityProvider := stscreds.NewWebIdentityRoleProvider(
				sts.NewFromConfig(baseCfg),
				authConfig.GlobalRoleARN,
				stscreds.IdentityTokenFile(authConfig.IDTokenFile),
				func(opt *stscreds.WebIdentityRoleOptions) {
					opt.Duration = defaultIntermediateDuration
				},
			)
			baseCfg.Credentials = aws.NewCredentialsCache(webIdentityProvider)

			// Step 2: Assume the customer's role from the global role session.
			// ExternalID follows the Cloudbeat/Beats convention: ResourceID-ExternalID.
			assumeRoleProvider := stscreds.NewAssumeRoleProvider(
				sts.NewFromConfig(baseCfg),
				authConfig.RoleARN,
				func(aro *stscreds.AssumeRoleOptions) {
					aro.RoleSessionName = sessionName
					aro.Duration = duration
					if authConfig.CloudResourceID != "" && authConfig.ExternalID != "" {
						aro.ExternalID = aws.String(authConfig.CloudResourceID + "-" + authConfig.ExternalID)
					} else if authConfig.ExternalID != "" {
						aro.ExternalID = aws.String(authConfig.ExternalID)
					}
				},
			)
			baseCfg.Credentials = aws.NewCredentialsCache(assumeRoleProvider)

			logger.Info("AWS identity federation OIDC credential chain configured",
				zap.String("global_role", authConfig.GlobalRoleARN),
				zap.String("customer_role", authConfig.RoleARN),
			)
		}

	default:
		logger.Info("Using default AWS credentials (testing)")
	}

	return &AWSVerifier{
		logger:     logger,
		baseConfig: baseCfg,
		configured: true,
		authConfig: authConfig,
		httpClient: httpClient,
	}, nil
}

// ProviderType returns the provider type.
func (v *AWSVerifier) ProviderType() ProviderType {
	return ProviderAWS
}

// Close releases resources, including closing idle HTTP connections.
func (v *AWSVerifier) Close() error {
	if v.httpClient != nil {
		v.httpClient.CloseIdleConnections()
	}
	return nil
}

// Verify checks if an AWS permission is granted using IAM policy simulation.
// For CSPM and asset inventory integrations, policy attachment is verified
// instead via iam:ListAttachedRolePolicies.
func (v *AWSVerifier) Verify(ctx context.Context, permission Permission, providerCfg ProviderConfig) Result {
	start := time.Now()

	if !v.configured {
		return Result{
			Status:       StatusError,
			ErrorCode:    "ConfigurationError",
			ErrorMessage: "AWS credentials not configured",
			Duration:     time.Since(start),
		}
	}

	cfg := v.baseConfig.Copy()
	if providerCfg.Region != "" {
		cfg.Region = providerCfg.Region
	}

	v.logger.Debug("Verifying AWS permission",
		zap.String("action", permission.Action),
		zap.String("region", cfg.Region),
		zap.String("method", string(permission.Method)),
	)

	var result Result
	if permission.Method == MethodPolicyAttachmentCheck {
		result = v.verifyPolicyAttachment(ctx, cfg, permission.Action)
	} else {
		result = v.simulatePrincipalPolicy(ctx, cfg, permission.Action)
	}

	result.Duration = time.Since(start)
	return result
}

// simulatePrincipalPolicy checks whether the currently assumed role has the
// given IAM action using iam:SimulatePrincipalPolicy. This is the authoritative
// permission check: it evaluates all applicable IAM policies (identity-based,
// resource-based, SCPs, permission boundaries) and returns the effective
// decision without making any data-plane API calls.
func (v *AWSVerifier) simulatePrincipalPolicy(ctx context.Context, cfg aws.Config, action string) Result {
	callerARN, err := v.getCallerARN(ctx, cfg)
	if err != nil {
		return v.handleAWSError(err, "sts:GetCallerIdentity")
	}

	iamClient := iam.NewFromConfig(cfg)
	resp, err := iamClient.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(callerARN),
		ActionNames:     []string{action},
		ResourceArns:    []string{"*"},
	})
	if err != nil {
		return v.handleAWSError(err, "iam:SimulatePrincipalPolicy")
	}

	if len(resp.EvaluationResults) == 0 {
		return Result{
			Status:       StatusError,
			ErrorCode:    "NoSimulationResult",
			ErrorMessage: "no simulation result returned for action: " + action,
			Endpoint:     "iam:SimulatePrincipalPolicy",
		}
	}

	evalResult := resp.EvaluationResults[0]
	if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
		return Result{
			Status:   StatusGranted,
			Endpoint: "iam:SimulatePrincipalPolicy",
		}
	}
	return Result{
		Status:       StatusDenied,
		ErrorCode:    string(evalResult.EvalDecision),
		ErrorMessage: fmt.Sprintf("permission %s denied by IAM policy simulation: %s", action, evalResult.EvalDecision),
		Endpoint:     "iam:SimulatePrincipalPolicy",
	}
}

// getCallerARN returns the IAM role ARN of the current principal, caching the
// result across calls. The ARN is converted from an assumed-role session ARN to
// the underlying role ARN required by iam:SimulatePrincipalPolicy.
func (v *AWSVerifier) getCallerARN(ctx context.Context, cfg aws.Config) (string, error) {
	v.callerARNMu.Lock()
	defer v.callerARNMu.Unlock()
	if v.cachedCallerARN != "" {
		return v.cachedCallerARN, nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	v.cachedCallerARN = toRoleARN(aws.ToString(identity.Arn))
	return v.cachedCallerARN, nil
}

// toRoleARN converts an assumed-role session ARN to the underlying IAM role ARN.
// iam:SimulatePrincipalPolicy requires an IAM role ARN, not an assumed-role ARN.
//
// Example:
//
//	arn:aws:sts::123456789012:assumed-role/MyRole/session
//	→ arn:aws:iam::123456789012:role/MyRole
func toRoleARN(callerARN string) string {
	const assumedRoleInfix = ":assumed-role/"
	if !strings.Contains(callerARN, assumedRoleInfix) {
		return callerARN // already a user or role ARN
	}
	parts := strings.Split(callerARN, ":")
	if len(parts) < 6 {
		return callerARN
	}
	accountID := parts[4]
	resource := parts[5] // assumed-role/ROLE_NAME/SESSION
	roleParts := strings.SplitN(resource, "/", 3)
	if len(roleParts) < 2 {
		return callerARN
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleParts[1])
}

// verifyPolicyAttachment checks whether a specific AWS managed policy is
// attached to the currently assumed role. It uses sts:GetCallerIdentity to
// discover the role name, then iam:ListAttachedRolePolicies to look for the
// target policy ARN.
//
// This method is used for CSPM and asset inventory integrations that require
// specific managed policy attachment rather than individual IAM actions.
func (v *AWSVerifier) verifyPolicyAttachment(ctx context.Context, cfg aws.Config, policyARN string) Result {
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return v.handleAWSError(err, "sts:GetCallerIdentity")
	}

	// ARN format: arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION
	arnStr := aws.ToString(identity.Arn)
	parts := strings.Split(arnStr, "/")
	if len(parts) < 2 {
		return Result{
			Status:       StatusError,
			ErrorCode:    "InvalidARN",
			ErrorMessage: "cannot extract role name from ARN: " + arnStr,
			Endpoint:     "iam:ListAttachedRolePolicies",
		}
	}
	roleName := parts[1]

	iamClient := iam.NewFromConfig(cfg)
	paginator := iam.NewListAttachedRolePoliciesPaginator(iamClient, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})

	for paginator.HasMorePages() {
		page, pageErr := paginator.NextPage(ctx)
		if pageErr != nil {
			return v.handleAWSError(pageErr, "iam:ListAttachedRolePolicies")
		}
		for _, policy := range page.AttachedPolicies {
			if aws.ToString(policy.PolicyArn) == policyARN {
				return Result{
					Status:   StatusGranted,
					Endpoint: fmt.Sprintf("iam:ListAttachedRolePolicies (found %s on role %s)", policyARN, roleName),
				}
			}
		}
	}

	return Result{
		Status:       StatusDenied,
		ErrorCode:    "PolicyNotAttached",
		ErrorMessage: fmt.Sprintf("managed policy %s is not attached to role %s", policyARN, roleName),
		Endpoint:     "iam:ListAttachedRolePolicies",
	}
}

// handleAWSError converts an AWS error to a verification result.
func (v *AWSVerifier) handleAWSError(err error, endpoint string) Result {
	if err == nil {
		return Result{
			Status:   StatusGranted,
			Endpoint: endpoint,
		}
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()

		// Check for access denied errors
		if isAccessDeniedError(code) {
			return Result{
				Status:       StatusDenied,
				ErrorCode:    code,
				ErrorMessage: apiErr.ErrorMessage(),
				Endpoint:     endpoint,
			}
		}

		// Other errors are treated as errors, not denials
		return Result{
			Status:       StatusError,
			ErrorCode:    code,
			ErrorMessage: apiErr.ErrorMessage(),
			Endpoint:     endpoint,
		}
	}

	// Non-API errors
	return Result{
		Status:       StatusError,
		ErrorMessage: err.Error(),
		Endpoint:     endpoint,
	}
}

// isAccessDeniedError checks if an error code indicates access denied.
func isAccessDeniedError(code string) bool {
	accessDeniedCodes := []string{
		"AccessDenied",
		"AccessDeniedException",
		"UnauthorizedAccess",
		"UnauthorizedOperation",
		"AuthorizationError",
		"Forbidden",
		"InvalidAccessKeyId",
		"SignatureDoesNotMatch",
	}

	for _, c := range accessDeniedCodes {
		if code == c {
			return true
		}
	}
	return false
}
