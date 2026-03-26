// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/smithy-go"
	"go.uber.org/zap"
)

const (
	defaultSessionName        = "verifier-receiver"
	defaultAssumeRoleDuration = 15 * time.Minute
	// Used by the cloud connector WebIdentity step. The global role session
	// is short-lived because it is only an intermediate step before assuming
	// the customer's role.
	defaultIntermediateDuration = 20 * time.Minute
)

// AWSVerifier implements permission verification for AWS.
type AWSVerifier struct {
	logger        *zap.Logger
	baseConfig    aws.Config
	configured    bool
	authConfig    AWSAuthConfig
	defaultRegion string
	httpClient    *http.Client
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
// Cloud connector mode (IDTokenFile + GlobalRoleARN set):
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

	if authConfig.DefaultRegion != "" {
		baseCfg.Region = authConfig.DefaultRegion
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
	case authConfig.IsCloudConnector():
		// Cloud connector OIDC flow: two-step credential chain.
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

		logger.Info("AWS cloud connector credential chain configured",
			zap.String("global_role", authConfig.GlobalRoleARN),
			zap.String("customer_role", authConfig.RoleARN),
		)

	default:
		logger.Info("Using default AWS credentials (testing)")
	}

	return &AWSVerifier{
		logger:        logger,
		baseConfig:    baseCfg,
		configured:    true,
		authConfig:    authConfig,
		defaultRegion: authConfig.DefaultRegion,
		httpClient:    httpClient,
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

// Verify checks if an AWS permission is granted.
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

	// Create region-specific config
	cfg := v.baseConfig.Copy()
	if providerCfg.Region != "" {
		cfg.Region = providerCfg.Region
	}

	// Parse the action to determine service and operation
	parts := strings.SplitN(permission.Action, ":", 2)
	if len(parts) != 2 {
		return Result{
			Status:       StatusError,
			ErrorCode:    "InvalidAction",
			ErrorMessage: "Invalid action format: " + permission.Action,
			Duration:     time.Since(start),
		}
	}

	service := strings.ToLower(parts[0])
	operation := parts[1]

	v.logger.Debug("Verifying AWS permission",
		zap.String("service", service),
		zap.String("operation", operation),
		zap.String("region", cfg.Region),
		zap.String("method", string(permission.Method)),
	)

	var result Result
	switch service {
	case "cloudtrail":
		result = v.verifyCloudTrail(ctx, cfg, operation)
	case "guardduty":
		result = v.verifyGuardDuty(ctx, cfg, operation)
	case "securityhub":
		result = v.verifySecurityHub(ctx, cfg, operation)
	case "s3":
		result = v.verifyS3(ctx, cfg, operation)
	case "ec2":
		result = v.verifyEC2(ctx, cfg, operation, permission.Method)
	case "cloudwatch":
		result = v.verifyCloudWatch(ctx, cfg, operation)
	case "sqs":
		result = v.verifySQS(ctx, cfg, operation)
	case "logs":
		result = v.verifyCloudWatchLogs(ctx, cfg, operation)
	case "wafv2":
		result = v.verifyWAFv2(ctx, cfg, operation)
	case "route53":
		result = v.verifyRoute53(ctx, cfg, operation)
	case "elasticloadbalancing":
		result = v.verifyELB(ctx, cfg, operation)
	case "cloudfront":
		result = v.verifyCloudFront(ctx, cfg, operation)
	case "iam":
		result = v.verifyIAM(ctx, cfg, operation)
	case "config":
		result = v.verifyConfig(ctx, cfg, operation)
	case "rds":
		result = v.verifyRDS(ctx, cfg, operation)
	default:
		if permission.Method == MethodPolicyAttachmentCheck {
			result = v.verifyPolicyAttachment(ctx, cfg, permission.Action)
		} else {
			result = Result{
				Status:       StatusSkipped,
				ErrorMessage: "Unsupported AWS service: " + service,
			}
		}
	}

	result.Duration = time.Since(start)
	return result
}

// verifyCloudTrail verifies CloudTrail permissions.
func (v *AWSVerifier) verifyCloudTrail(ctx context.Context, cfg aws.Config, operation string) Result {
	client := cloudtrail.NewFromConfig(cfg)

	switch operation {
	case "LookupEvents":
		// Make a minimal API call to check permission
		_, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			MaxResults: aws.Int32(1),
		})
		return v.handleAWSError(err, "cloudtrail:LookupEvents")

	case "DescribeTrails":
		_, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
		return v.handleAWSError(err, "cloudtrail:DescribeTrails")

	case "GetTrailStatus":
		// Need a trail name - try listing first
		trails, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
		if err != nil {
			return v.handleAWSError(err, "cloudtrail:GetTrailStatus")
		}
		if len(trails.TrailList) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "cloudtrail:GetTrailStatus (no trails to check)",
			}
		}
		_, err = client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trails.TrailList[0].Name,
		})
		return v.handleAWSError(err, "cloudtrail:GetTrailStatus")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported CloudTrail operation: " + operation,
		}
	}
}

// verifyGuardDuty verifies GuardDuty permissions.
func (v *AWSVerifier) verifyGuardDuty(ctx context.Context, cfg aws.Config, operation string) Result {
	client := guardduty.NewFromConfig(cfg)

	switch operation {
	case "ListDetectors":
		_, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{
			MaxResults: aws.Int32(1),
		})
		return v.handleAWSError(err, "guardduty:ListDetectors")

	case "GetFindings":
		detectors, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{
			MaxResults: aws.Int32(1),
		})
		if err != nil {
			return v.handleAWSError(err, "guardduty:GetFindings")
		}
		if len(detectors.DetectorIds) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "guardduty:GetFindings (no detectors configured)",
			}
		}
		// Call GetFindings with an empty finding IDs list. This exercises the
		// guardduty:GetFindings IAM permission and returns an empty result set
		// rather than an error.
		_, err = client.GetFindings(ctx, &guardduty.GetFindingsInput{
			DetectorId: aws.String(detectors.DetectorIds[0]),
			FindingIds: []string{},
		})
		return v.handleAWSError(err, "guardduty:GetFindings")

	case "ListFindings":
		detectors, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{
			MaxResults: aws.Int32(1),
		})
		if err != nil {
			return v.handleAWSError(err, "guardduty:ListFindings")
		}
		if len(detectors.DetectorIds) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "guardduty:ListFindings (no detectors configured)",
			}
		}
		_, err = client.ListFindings(ctx, &guardduty.ListFindingsInput{
			DetectorId: aws.String(detectors.DetectorIds[0]),
			MaxResults: aws.Int32(1),
		})
		return v.handleAWSError(err, "guardduty:ListFindings")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported GuardDuty operation: " + operation,
		}
	}
}

// verifySecurityHub verifies Security Hub permissions.
func (v *AWSVerifier) verifySecurityHub(ctx context.Context, cfg aws.Config, operation string) Result {
	client := securityhub.NewFromConfig(cfg)

	switch operation {
	case "GetFindings":
		_, err := client.GetFindings(ctx, &securityhub.GetFindingsInput{
			MaxResults: aws.Int32(1),
		})
		return v.handleAWSError(err, "securityhub:GetFindings")

	case "DescribeHub":
		_, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
		return v.handleAWSError(err, "securityhub:DescribeHub")

	case "BatchGetSecurityControls":
		// This requires control IDs, skip if we don't have them
		return Result{
			Status:   StatusSkipped,
			Endpoint: "securityhub:BatchGetSecurityControls (requires control IDs)",
		}

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Security Hub operation: " + operation,
		}
	}
}

// verifyS3 verifies S3 permissions.
func (v *AWSVerifier) verifyS3(ctx context.Context, cfg aws.Config, operation string) Result {
	client := s3.NewFromConfig(cfg)

	switch operation {
	case "ListBucket":
		// Use HeadBucket on a known bucket to verify s3:ListBucket.
		// ListBuckets checks s3:ListAllMyBuckets which is a different permission.
		// If no specific bucket is available, fall back to ListBuckets as a basic connectivity check.
		buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return v.handleAWSError(err, "s3:ListBucket")
		}
		if len(buckets.Buckets) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "s3:ListBucket (no buckets to check, ListBuckets succeeded)",
			}
		}
		_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: buckets.Buckets[0].Name,
		})
		return v.handleAWSError(err, "s3:ListBucket")

	case "GetObject":
		// s3:GetObject is bucket/key-specific and cannot be fully verified without
		// a target object. Use HeadBucket as a proxy to confirm the role has some
		// level of S3 access to the account's buckets.
		buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return v.handleAWSError(err, "s3:GetObject")
		}
		if len(buckets.Buckets) == 0 {
			return Result{
				Status:   StatusSkipped,
				Endpoint: "s3:GetObject (no buckets available for verification)",
			}
		}
		_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: buckets.Buckets[0].Name,
		})
		if err != nil {
			return v.handleAWSError(err, "s3:GetObject")
		}
		return Result{
			Status:   StatusGranted,
			Endpoint: "s3:GetObject (verified via HeadBucket - full verification requires bucket/key)",
		}

	case "GetBucketLocation":
		buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return v.handleAWSError(err, "s3:GetBucketLocation")
		}
		if len(buckets.Buckets) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "s3:GetBucketLocation (no buckets to check)",
			}
		}
		_, err = client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: buckets.Buckets[0].Name,
		})
		return v.handleAWSError(err, "s3:GetBucketLocation")

	case "GetBucketAcl":
		buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return v.handleAWSError(err, "s3:GetBucketAcl")
		}
		if len(buckets.Buckets) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "s3:GetBucketAcl (no buckets to check)",
			}
		}
		_, err = client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: buckets.Buckets[0].Name,
		})
		return v.handleAWSError(err, "s3:GetBucketAcl")

	case "ListAllMyBuckets":
		_, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		return v.handleAWSError(err, "s3:ListAllMyBuckets")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported S3 operation: " + operation,
		}
	}
}

// verifyEC2 verifies EC2 permissions, using DryRun where appropriate.
func (v *AWSVerifier) verifyEC2(ctx context.Context, cfg aws.Config, operation string, method VerificationMethod) Result {
	client := ec2.NewFromConfig(cfg)

	switch operation {
	case "DescribeInstances":
		if method == MethodDryRun {
			// Use DryRun to check permission without actually running
			_, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
				DryRun:     aws.Bool(true),
				MaxResults: aws.Int32(5),
			})
			return v.handleEC2DryRunError(err, "ec2:DescribeInstances")
		}
		_, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			MaxResults: aws.Int32(5),
		})
		return v.handleAWSError(err, "ec2:DescribeInstances")

	case "DescribeRegions":
		_, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
		return v.handleAWSError(err, "ec2:DescribeRegions")

	case "DescribeFlowLogs":
		_, err := client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
			MaxResults: aws.Int32(5),
		})
		return v.handleAWSError(err, "ec2:DescribeFlowLogs")

	case "DescribeSecurityGroups":
		_, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			MaxResults: aws.Int32(5),
		})
		return v.handleAWSError(err, "ec2:DescribeSecurityGroups")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported EC2 operation: " + operation,
		}
	}
}

// verifyCloudWatch verifies CloudWatch permissions.
func (v *AWSVerifier) verifyCloudWatch(ctx context.Context, cfg aws.Config, operation string) Result {
	client := cloudwatch.NewFromConfig(cfg)

	switch operation {
	case "GetMetricData":
		_, err := client.ListMetrics(ctx, &cloudwatch.ListMetricsInput{})
		return v.handleAWSError(err, "cloudwatch:GetMetricData (verified via ListMetrics - different IAM permission)")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported CloudWatch operation: " + operation,
		}
	}
}

// verifySQS verifies SQS permissions.
func (v *AWSVerifier) verifySQS(ctx context.Context, cfg aws.Config, operation string) Result {
	client := sqs.NewFromConfig(cfg)

	switch operation {
	case "ReceiveMessage", "DeleteMessage":
		_, err := client.ListQueues(ctx, &sqs.ListQueuesInput{
			MaxResults: aws.Int32(1),
		})
		return v.handleAWSError(err, "sqs:"+operation+" (verified via ListQueues - different IAM permission)")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported SQS operation: " + operation,
		}
	}
}

// verifyCloudWatchLogs verifies CloudWatch Logs permissions.
func (v *AWSVerifier) verifyCloudWatchLogs(ctx context.Context, cfg aws.Config, operation string) Result {
	client := cloudwatchlogs.NewFromConfig(cfg)

	switch operation {
	case "FilterLogEvents":
		// FilterLogEvents requires a log group; use DescribeLogGroups to find one.
		groups, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			Limit: aws.Int32(1),
		})
		if err != nil {
			return v.handleAWSError(err, "logs:FilterLogEvents")
		}
		if len(groups.LogGroups) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "logs:FilterLogEvents (no log groups to check)",
			}
		}
		_, err = client.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{
			LogGroupName: groups.LogGroups[0].LogGroupName,
			Limit:        aws.Int32(1),
		})
		return v.handleAWSError(err, "logs:FilterLogEvents")

	case "DescribeLogGroups":
		_, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			Limit: aws.Int32(1),
		})
		return v.handleAWSError(err, "logs:DescribeLogGroups")

	case "DescribeLogStreams":
		groups, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			Limit: aws.Int32(1),
		})
		if err != nil {
			return v.handleAWSError(err, "logs:DescribeLogStreams")
		}
		if len(groups.LogGroups) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "logs:DescribeLogStreams (no log groups to check)",
			}
		}
		_, err = client.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
			LogGroupName: groups.LogGroups[0].LogGroupName,
			Limit:        aws.Int32(1),
		})
		return v.handleAWSError(err, "logs:DescribeLogStreams")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported CloudWatch Logs operation: " + operation,
		}
	}
}

// verifyWAFv2 verifies WAFv2 permissions.
func (v *AWSVerifier) verifyWAFv2(ctx context.Context, cfg aws.Config, operation string) Result {
	client := wafv2.NewFromConfig(cfg)

	switch operation {
	case "ListWebACLs":
		_, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope: wafv2types.ScopeRegional,
			Limit: aws.Int32(1),
		})
		return v.handleAWSError(err, "wafv2:ListWebACLs")

	case "GetWebACL":
		// GetWebACL requires a WebACL ID; list first to find one.
		acls, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope: wafv2types.ScopeRegional,
			Limit: aws.Int32(1),
		})
		if err != nil {
			return v.handleAWSError(err, "wafv2:GetWebACL")
		}
		if len(acls.WebACLs) == 0 {
			return Result{
				Status:   StatusGranted,
				Endpoint: "wafv2:GetWebACL (no WebACLs to check)",
			}
		}
		_, err = client.GetWebACL(ctx, &wafv2.GetWebACLInput{
			Name:  acls.WebACLs[0].Name,
			Id:    acls.WebACLs[0].Id,
			Scope: wafv2types.ScopeRegional,
		})
		return v.handleAWSError(err, "wafv2:GetWebACL")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported WAFv2 operation: " + operation,
		}
	}
}

// verifyRoute53 verifies Route 53 permissions.
func (v *AWSVerifier) verifyRoute53(ctx context.Context, cfg aws.Config, operation string) Result {
	client := route53.NewFromConfig(cfg)

	switch operation {
	case "ListHostedZones":
		_, err := client.ListHostedZones(ctx, &route53.ListHostedZonesInput{
			MaxItems: aws.Int32(1),
		})
		return v.handleAWSError(err, "route53:ListHostedZones")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Route53 operation: " + operation,
		}
	}
}

// verifyELB verifies Elastic Load Balancing permissions.
func (v *AWSVerifier) verifyELB(ctx context.Context, cfg aws.Config, operation string) Result {
	client := elasticloadbalancingv2.NewFromConfig(cfg)

	switch operation {
	case "DescribeLoadBalancers":
		_, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
			PageSize: aws.Int32(1),
		})
		return v.handleAWSError(err, "elasticloadbalancing:DescribeLoadBalancers")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported ELB operation: " + operation,
		}
	}
}

// verifyCloudFront verifies CloudFront permissions.
func (v *AWSVerifier) verifyCloudFront(ctx context.Context, cfg aws.Config, operation string) Result {
	client := cloudfront.NewFromConfig(cfg)

	switch operation {
	case "ListDistributions":
		_, err := client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{
			MaxItems: aws.Int32(1),
		})
		return v.handleAWSError(err, "cloudfront:ListDistributions")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported CloudFront operation: " + operation,
		}
	}
}

// verifyIAM verifies IAM permissions.
func (v *AWSVerifier) verifyIAM(ctx context.Context, cfg aws.Config, operation string) Result {
	client := iam.NewFromConfig(cfg)

	switch operation {
	case "GetAccountSummary":
		_, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
		return v.handleAWSError(err, "iam:GetAccountSummary")

	case "ListUsers":
		_, err := client.ListUsers(ctx, &iam.ListUsersInput{
			MaxItems: aws.Int32(1),
		})
		return v.handleAWSError(err, "iam:ListUsers")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported IAM operation: " + operation,
		}
	}
}

// verifyConfig verifies AWS Config permissions.
func (v *AWSVerifier) verifyConfig(ctx context.Context, cfg aws.Config, operation string) Result {
	client := configservice.NewFromConfig(cfg)

	switch operation {
	case "DescribeComplianceByConfigRule":
		_, err := client.DescribeComplianceByConfigRule(ctx, &configservice.DescribeComplianceByConfigRuleInput{})
		return v.handleAWSError(err, "config:DescribeComplianceByConfigRule")

	case "DescribeConfigRules":
		_, err := client.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{})
		return v.handleAWSError(err, "config:DescribeConfigRules")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported Config operation: " + operation,
		}
	}
}

// verifyRDS verifies RDS permissions.
func (v *AWSVerifier) verifyRDS(ctx context.Context, cfg aws.Config, operation string) Result {
	client := rds.NewFromConfig(cfg)

	switch operation {
	case "DescribeDBInstances":
		_, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
			MaxRecords: aws.Int32(20),
		})
		return v.handleAWSError(err, "rds:DescribeDBInstances")

	default:
		return Result{
			Status:       StatusSkipped,
			ErrorMessage: "Unsupported RDS operation: " + operation,
		}
	}
}

// verifyPolicyAttachment checks whether a specific AWS managed policy is
// attached to the currently assumed role. It uses sts:GetCallerIdentity to
// discover the role name, then iam:ListAttachedRolePolicies to look for the
// target policy ARN.
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

// handleEC2DryRunError handles EC2 DryRun responses.
// DryRun returns an error even on success - we need to check the error type.
func (v *AWSVerifier) handleEC2DryRunError(err error, endpoint string) Result {
	if err == nil {
		// Unexpected - DryRun should always return an error
		return Result{
			Status:   StatusGranted,
			Endpoint: endpoint,
		}
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()

		// DryRunOperation means the permission check passed
		if code == "DryRunOperation" {
			return Result{
				Status:   StatusGranted,
				Endpoint: endpoint + " (DryRun)",
			}
		}

		// UnauthorizedOperation means access denied
		if code == "UnauthorizedOperation" || isAccessDeniedError(code) {
			return Result{
				Status:       StatusDenied,
				ErrorCode:    code,
				ErrorMessage: apiErr.ErrorMessage(),
				Endpoint:     endpoint + " (DryRun)",
			}
		}

		// Other errors
		return Result{
			Status:       StatusError,
			ErrorCode:    code,
			ErrorMessage: apiErr.ErrorMessage(),
			Endpoint:     endpoint,
		}
	}

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
