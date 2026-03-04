// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver"

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"
)

// Type aliases for verifier package types to avoid duplication.
// The canonical definitions live in the internal/verifier package.
type VerificationMethod = verifier.VerificationMethod

// Re-export verification method constants for use by registry callers.
var (
	MethodAPICall   = verifier.MethodAPICall
	MethodDryRun    = verifier.MethodDryRun
	MethodHTTPProbe = verifier.MethodHTTPProbe
	MethodGraphQL   = verifier.MethodGraphQL
)

// PermissionStatus represents the result of a permission verification.
type PermissionStatus string

const (
	StatusGranted PermissionStatus = PermissionStatus(verifier.StatusGranted)
	StatusDenied  PermissionStatus = PermissionStatus(verifier.StatusDenied)
	StatusError   PermissionStatus = PermissionStatus(verifier.StatusError)
	StatusSkipped PermissionStatus = PermissionStatus(verifier.StatusSkipped)
	StatusPending PermissionStatus = "pending"
)

// Permission represents a single permission to verify.
type Permission struct {
	// Action is the permission action (e.g., "cloudtrail:LookupEvents", "s3:GetObject").
	Action string

	// Required indicates if this permission is required for the integration to function.
	Required bool

	// Method is the verification method to use.
	Method VerificationMethod

	// APIEndpoint is the API endpoint to call (for http_probe, graphql_query methods).
	APIEndpoint string

	// Category is an optional categorization (e.g., "data_access", "management").
	Category string
}

// IntegrationPermissions defines the permissions required by an integration type.
type IntegrationPermissions struct {
	// Provider identifies the cloud/service provider.
	Provider verifier.ProviderType

	// Permissions is the list of permissions required by this integration.
	Permissions []Permission
}

// VersionedPermissions associates a semver constraint with a set of integration permissions.
// The constraint string follows semver syntax (e.g., ">=2.0.0", ">=1.0.0,<2.0.0").
type VersionedPermissions struct {
	// ConstraintStr is the raw semver constraint string for display/logging.
	ConstraintStr string

	// Constraint is the parsed semver constraint used for matching.
	Constraint *semver.Constraints

	// Permissions is the permission set for integrations matching this constraint.
	Permissions IntegrationPermissions
}

// PermissionRegistry maintains the mapping of integration types to their required permissions.
// The receiver owns this mapping - Fleet API only provides the integration context.
//
// Each integration type can have multiple versioned permission sets. When looking up
// permissions, the registry matches the provided integration version against the
// registered semver constraints and returns the first match (newest-first order).
type PermissionRegistry struct {
	integrations map[string][]VersionedPermissions
}

// NewPermissionRegistry creates a new permission registry with default mappings.
func NewPermissionRegistry() *PermissionRegistry {
	registry := &PermissionRegistry{
		integrations: make(map[string][]VersionedPermissions),
	}

	// Register all provider integrations
	registry.registerAWSIntegrations()
	registry.registerAzureIntegrations()
	registry.registerGCPIntegrations()
	registry.registerOktaIntegrations()

	return registry
}

// register adds a versioned permission set for an integration type.
// Entries should be registered newest-first so that the first entry serves as the
// default when no version is specified. The constraint string follows semver syntax
// (e.g., ">=2.0.0", ">=1.0.0,<2.0.0", ">=0.0.0").
func (r *PermissionRegistry) register(integrationType string, constraintStr string, perms IntegrationPermissions) {
	constraint, err := semver.NewConstraint(constraintStr)
	if err != nil {
		panic(fmt.Sprintf("invalid semver constraint %q for integration %q: %v", constraintStr, integrationType, err))
	}

	r.integrations[integrationType] = append(r.integrations[integrationType], VersionedPermissions{
		ConstraintStr: constraintStr,
		Constraint:    constraint,
		Permissions:   perms,
	})
}

// GetPermissions returns the permissions required for an integration type and version.
// If version is empty, the first (latest) registered permission set is returned.
// If no constraint matches the version, nil is returned.
func (r *PermissionRegistry) GetPermissions(integrationType string, version string) *IntegrationPermissions {
	entries, ok := r.integrations[integrationType]
	if !ok || len(entries) == 0 {
		return nil
	}

	// If no version specified, return the first (latest) entry
	if version == "" {
		perms := entries[0].Permissions
		return &perms
	}

	// Parse the provided version
	v, err := semver.NewVersion(version)
	if err != nil {
		// If the version string is not valid semver, fall back to the latest entry
		perms := entries[0].Permissions
		return &perms
	}

	// Find the first matching constraint
	for i := range entries {
		if entries[i].Constraint.Check(v) {
			perms := entries[i].Permissions
			return &perms
		}
	}

	// No matching constraint found
	return nil
}

// IsSupported returns true if the integration type is registered in the registry.
func (r *PermissionRegistry) IsSupported(integrationType string) bool {
	entries, ok := r.integrations[integrationType]
	return ok && len(entries) > 0
}

// SupportedIntegrations returns a list of all supported integration types.
func (r *PermissionRegistry) SupportedIntegrations() []string {
	integrations := make([]string, 0, len(r.integrations))
	for k := range r.integrations {
		integrations = append(integrations, k)
	}
	return integrations
}

// SupportedIntegrationsByProvider returns integration types grouped by provider.
func (r *PermissionRegistry) SupportedIntegrationsByProvider() map[verifier.ProviderType][]string {
	byProvider := make(map[verifier.ProviderType][]string)
	for integrationType, entries := range r.integrations {
		if len(entries) > 0 {
			byProvider[entries[0].Permissions.Provider] = append(byProvider[entries[0].Permissions.Provider], integrationType)
		}
	}
	return byProvider
}

// GetVersionConstraints returns the version constraints registered for an integration type.
// Returns nil if the integration type is not registered.
func (r *PermissionRegistry) GetVersionConstraints(integrationType string) []string {
	entries, ok := r.integrations[integrationType]
	if !ok {
		return nil
	}
	constraints := make([]string, len(entries))
	for i, entry := range entries {
		constraints[i] = entry.ConstraintStr
	}
	return constraints
}

// registerAWSIntegrations registers all AWS-based integrations.
func (r *PermissionRegistry) registerAWSIntegrations() {
	// AWS CloudTrail - commonly used for security auditing
	// https://www.elastic.co/docs/current/integrations/aws/cloudtrail
	//
	// v2.0.0+: Added sqs:DeleteMessage as required (queue-based ingestion became default)
	r.register("aws_cloudtrail", ">=2.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "cloudtrail:LookupEvents",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "cloudtrail:DescribeTrails",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "cloudtrail:GetTrailStatus",
				Required: false,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "s3:GetObject",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "s3:ListBucket",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "sqs:ReceiveMessage",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "sqs:DeleteMessage",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})
	// v1.x: Original permission set (SQS optional)
	r.register("aws_cloudtrail", ">=1.0.0,<2.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "cloudtrail:LookupEvents",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "cloudtrail:DescribeTrails",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "cloudtrail:GetTrailStatus",
				Required: false,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "s3:GetObject",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "s3:ListBucket",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "sqs:ReceiveMessage",
				Required: false,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "sqs:DeleteMessage",
				Required: false,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// AWS GuardDuty - threat detection service
	r.register("aws_guardduty", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "guardduty:ListDetectors",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "guardduty:GetFindings",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "guardduty:ListFindings",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// AWS Security Hub - security findings aggregation
	r.register("aws_securityhub", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "securityhub:GetFindings",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "securityhub:BatchGetSecurityControls",
				Required: false,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "securityhub:DescribeHub",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
		},
	})

	// AWS S3 - storage access logs
	r.register("aws_s3", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "s3:ListBucket",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "s3:GetObject",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "s3:GetBucketLocation",
				Required: false,
				Method:   MethodAPICall,
				Category: "management",
			},
		},
	})

	// AWS EC2 - compute instance metrics
	r.register("aws_ec2", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "ec2:DescribeInstances",
				Required: true,
				Method:   MethodDryRun,
				Category: "data_access",
			},
			{
				Action:   "ec2:DescribeRegions",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "cloudwatch:GetMetricData",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// AWS VPC Flow Logs
	r.register("aws_vpcflow", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "logs:FilterLogEvents",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "logs:DescribeLogGroups",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "logs:DescribeLogStreams",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "ec2:DescribeFlowLogs",
				Required: false,
				Method:   MethodAPICall,
				Category: "management",
			},
		},
	})

	// AWS WAF - Web Application Firewall logs
	r.register("aws_waf", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "wafv2:GetWebACL",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "wafv2:ListWebACLs",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "s3:GetObject",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "s3:ListBucket",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// AWS Route53 - DNS query logs
	r.register("aws_route53", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "logs:FilterLogEvents",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "logs:DescribeLogGroups",
				Required: true,
				Method:   MethodAPICall,
				Category: "management",
			},
			{
				Action:   "route53:ListHostedZones",
				Required: false,
				Method:   MethodAPICall,
				Category: "management",
			},
		},
	})

	// AWS ELB - Elastic Load Balancer access logs
	r.register("aws_elb", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "s3:GetObject",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "s3:ListBucket",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "elasticloadbalancing:DescribeLoadBalancers",
				Required: false,
				Method:   MethodAPICall,
				Category: "management",
			},
		},
	})

	// AWS CloudFront - CDN access logs
	r.register("aws_cloudfront", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "s3:GetObject",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "s3:ListBucket",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "cloudfront:ListDistributions",
				Required: false,
				Method:   MethodAPICall,
				Category: "management",
			},
		},
	})

	// AWS CSPM - Cloud Security Posture Management
	// Requires the SecurityAudit managed policy. These are representative checks
	// that confirm the policy is attached.
	r.register("aws_cspm", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "iam:GetAccountSummary",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "ec2:DescribeInstances",
				Required: true,
				Method:   MethodDryRun,
				Category: "security_posture",
			},
			{
				Action:   "s3:GetBucketAcl",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "cloudtrail:DescribeTrails",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "config:DescribeComplianceByConfigRule",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
		},
	})

	// AWS Asset Inventory - Cloud Asset Discovery
	// Requires the SecurityAudit managed policy. These checks verify access to
	// the core resource types inventoried by Cloud Asset Discovery.
	r.register("aws_asset_inventory", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "ec2:DescribeInstances",
				Required: true,
				Method:   MethodDryRun,
				Category: "asset_inventory",
			},
			{
				Action:   "ec2:DescribeSecurityGroups",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "s3:ListAllMyBuckets",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "iam:ListUsers",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "rds:DescribeDBInstances",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
		},
	})
}

// registerAzureIntegrations registers all Azure-based integrations.
func (r *PermissionRegistry) registerAzureIntegrations() {
	// Azure Activity Logs
	r.register("azure_activitylogs", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAzure,
		Permissions: []Permission{
			{
				Action:   "Microsoft.Insights/eventtypes/values/Read",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// Azure Audit Logs
	r.register("azure_auditlogs", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAzure,
		Permissions: []Permission{
			{
				Action:   "Microsoft.Insights/eventtypes/values/Read",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// Azure Blob Storage
	r.register("azure_blob_storage", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAzure,
		Permissions: []Permission{
			{
				Action:   "Microsoft.Storage/storageAccounts/blobServices/containers/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// Azure CSPM - Cloud Security Posture Management
	// Requires Reader built-in role + custom role with Microsoft.Web permissions.
	r.register("azure_cspm", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAzure,
		Permissions: []Permission{
			{
				Action:   "Microsoft.Resources/subscriptions/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "Microsoft.Compute/virtualMachines/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "Microsoft.Storage/storageAccounts/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "Microsoft.Web/sites/config/Read",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
		},
	})

	// Azure Asset Inventory - Cloud Asset Discovery
	// Requires Reader built-in role.
	r.register("azure_asset_inventory", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAzure,
		Permissions: []Permission{
			{
				Action:   "Microsoft.Resources/subscriptions/resources/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "Microsoft.Compute/virtualMachines/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "Microsoft.Network/networkSecurityGroups/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "Microsoft.Storage/storageAccounts/read",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
		},
	})
}

// registerGCPIntegrations registers all GCP-based integrations.
func (r *PermissionRegistry) registerGCPIntegrations() {
	// GCP Audit Logs
	r.register("gcp_audit", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderGCP,
		Permissions: []Permission{
			{
				Action:   "logging.logEntries.list",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// GCP Cloud Storage
	r.register("gcp_storage", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderGCP,
		Permissions: []Permission{
			{
				Action:   "storage.objects.get",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
			{
				Action:   "storage.objects.list",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// GCP Pub/Sub
	r.register("gcp_pubsub", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderGCP,
		Permissions: []Permission{
			{
				Action:   "pubsub.subscriptions.consume",
				Required: true,
				Method:   MethodAPICall,
				Category: "data_access",
			},
		},
	})

	// GCP CSPM - Cloud Security Posture Management
	// Requires roles/cloudasset.viewer and roles/browser.
	r.register("gcp_cspm", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderGCP,
		Permissions: []Permission{
			{
				Action:   "cloudasset.assets.searchAllResources",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "resourcemanager.projects.get",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "compute.instances.list",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
			{
				Action:   "storage.buckets.list",
				Required: true,
				Method:   MethodAPICall,
				Category: "security_posture",
			},
		},
	})

	// GCP Asset Inventory - Cloud Asset Discovery
	// Requires roles/cloudasset.viewer and roles/browser.
	r.register("gcp_asset_inventory", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderGCP,
		Permissions: []Permission{
			{
				Action:   "cloudasset.assets.searchAllResources",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "resourcemanager.projects.get",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
			{
				Action:   "compute.instances.list",
				Required: true,
				Method:   MethodAPICall,
				Category: "asset_inventory",
			},
		},
	})
}

// registerOktaIntegrations is a placeholder for Okta-based integrations.
// Okta entries are intentionally not registered until an Okta verifier
// factory is implemented and wired in receiver.go. Registering them now
// would cause VerifierNotInitialized errors at runtime.
func (r *PermissionRegistry) registerOktaIntegrations() {
}
