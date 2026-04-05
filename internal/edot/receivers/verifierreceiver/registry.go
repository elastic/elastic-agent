// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver"

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"
)

// Type aliases for verifier package types to avoid duplication.
// The canonical definitions live in the internal/verifier package.
type VerificationMethod = verifier.VerificationMethod

// Re-export verification method constants for use by registry callers.
var (
	MethodAPICall               = verifier.MethodAPICall
	MethodDryRun                = verifier.MethodDryRun
	MethodHTTPProbe             = verifier.MethodHTTPProbe
	MethodGraphQL               = verifier.MethodGraphQL
	MethodPolicyAttachmentCheck = verifier.MethodPolicyAttachmentCheck
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

// Pre-release tag constants aligned with Kibana Fleet's getPackageReleaseLabel
// (x-pack/platform/plugins/shared/fleet/common/services/package_prerelease.ts).
const (
	PrereleaseTagPreview = "preview"
	PrereleaseTagRC      = "rc"
	PrereleaseTagBeta    = "beta"
)

// VersionedPermissions associates a semver constraint with a set of integration permissions.
// The constraint string follows semver syntax (e.g., ">=2.0.0", ">=1.0.0,<2.0.0").
type VersionedPermissions struct {
	// ConstraintStr is the raw semver constraint string for display/logging.
	ConstraintStr string

	// Constraint is the parsed semver constraint used for matching.
	Constraint *semver.Constraints

	// PrereleaseTag scopes this entry to a specific pre-release stage.
	// When empty, the entry applies to release (ga) versions and serves as
	// the fallback for pre-release versions that have no tag-specific entry.
	// Valid values: "", "beta", "preview", "rc".
	PrereleaseTag string

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
	// registry.registerOktaIntegrations()

	return registry
}

// register adds a versioned permission set for release (ga) versions of an integration type.
// Entries should be registered newest-first so that the first entry serves as the
// default when no version is specified. The constraint string follows semver syntax
// (e.g., ">=2.0.0", ">=1.0.0,<2.0.0", ">=0.0.0").
func (r *PermissionRegistry) register(integrationType string, constraintStr string, perms IntegrationPermissions) {
	r.registerWithTag(integrationType, constraintStr, "", perms)
}

// registerWithTag adds a versioned permission set scoped to a specific pre-release
// tag. Use an empty prereleaseTag for release (ga) versions. When GetPermissions
// receives a pre-release version (e.g., "2.17.0-beta1"), it first looks for entries
// matching the extracted tag ("beta"), then falls back to release entries.
func (r *PermissionRegistry) registerWithTag(integrationType string, constraintStr string, prereleaseTag string, perms IntegrationPermissions) {
	constraint, err := semver.NewConstraint(constraintStr)
	if err != nil {
		panic(fmt.Sprintf("invalid semver constraint %q for integration %q: %v", constraintStr, integrationType, err))
	}

	r.integrations[integrationType] = append(r.integrations[integrationType], VersionedPermissions{
		ConstraintStr: constraintStr,
		Constraint:    constraint,
		PrereleaseTag: prereleaseTag,
		Permissions:   perms,
	})
}

// GetPermissions returns the permissions required for an integration type and version.
// If version is empty, the first (latest) registered permission set is returned.
// If no constraint matches the version, nil is returned.
//
// Pre-release versions (e.g., "2.17.0-beta1", "3.3.0-preview05") are supported via
// a two-pass lookup:
//
//  1. Tag-specific pass: the pre-release tag is extracted (e.g., "beta") and matched
//     against entries registered with that PrereleaseTag.
//  2. Fallback pass: entries with an empty PrereleaseTag (release/ga) are tried.
//
// The base version (major.minor.patch without the pre-release suffix) is used for
// constraint checking because Masterminds/semver does not match pre-release versions
// against constraints that lack pre-release markers.
func (r *PermissionRegistry) GetPermissions(integrationType string, version string) *IntegrationPermissions {
	entries, ok := r.integrations[integrationType]
	if !ok || len(entries) == 0 {
		return nil
	}

	// If no version specified, return the first (latest) release entry
	if version == "" {
		return r.firstReleaseEntry(entries)
	}

	// Parse the provided version
	v, err := semver.NewVersion(version)
	if err != nil {
		// If the version string is not valid semver, fall back to the latest release entry
		return r.firstReleaseEntry(entries)
	}

	tag := extractPrereleaseTag(v)
	base := stripPrerelease(v)

	// Pass 1: look for entries matching the specific pre-release tag
	if tag != "" {
		for i := range entries {
			if entries[i].PrereleaseTag == tag && entries[i].Constraint.Check(base) {
				perms := entries[i].Permissions
				return &perms
			}
		}
	}

	// Pass 2: fall back to release (ga) entries
	for i := range entries {
		if entries[i].PrereleaseTag == "" && entries[i].Constraint.Check(base) {
			perms := entries[i].Permissions
			return &perms
		}
	}

	// No matching constraint found
	return nil
}

// firstReleaseEntry returns the first entry with an empty PrereleaseTag,
// which represents the latest release (ga) permission set.
func (r *PermissionRegistry) firstReleaseEntry(entries []VersionedPermissions) *IntegrationPermissions {
	for i := range entries {
		if entries[i].PrereleaseTag == "" {
			perms := entries[i].Permissions
			return &perms
		}
	}
	if len(entries) > 0 {
		perms := entries[0].Permissions
		return &perms
	}
	return nil
}

// stripPrerelease returns a version with only the major.minor.patch components,
// removing any pre-release suffix and build metadata. This is needed because
// Masterminds/semver does not match pre-release versions against constraints
// that lack pre-release markers (e.g., ">=2.0.0" won't match "2.17.0-beta1").
func stripPrerelease(v *semver.Version) *semver.Version {
	if v.Prerelease() == "" && v.Metadata() == "" {
		return v
	}
	stripped, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Patch()))
	if err != nil {
		return v
	}
	return stripped
}

// extractPrereleaseTag classifies a version's pre-release suffix into a tag.
// The classification follows the same priority as Kibana Fleet's getPackageReleaseLabel:
//   - major == 0 or pre-release contains "preview" --> "preview"
//   - pre-release contains "rc" --> "rc"
//   - any other pre-release --> "beta" (catch-all)
//   - no pre-release --> "" (ga/release)
func extractPrereleaseTag(v *semver.Version) string {
	pre := v.Prerelease()
	if v.Major() == 0 {
		return PrereleaseTagPreview
	}
	if pre == "" {
		return ""
	}
	if strings.Contains(pre, PrereleaseTagPreview) {
		return PrereleaseTagPreview
	}
	if strings.Contains(pre, PrereleaseTagRC) {
		return PrereleaseTagRC
	}
	return PrereleaseTagBeta
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
// Each string includes the pre-release tag when set (e.g., ">=2.0.0 [beta]").
// Returns nil if the integration type is not registered.
func (r *PermissionRegistry) GetVersionConstraints(integrationType string) []string {
	entries, ok := r.integrations[integrationType]
	if !ok {
		return nil
	}
	constraints := make([]string, len(entries))
	for i, entry := range entries {
		if entry.PrereleaseTag != "" {
			constraints[i] = fmt.Sprintf("%s [%s]", entry.ConstraintStr, entry.PrereleaseTag)
		} else {
			constraints[i] = entry.ConstraintStr
		}
	}
	return constraints
}

// registerAWSIntegrations registers all AWS-based integrations.
func (r *PermissionRegistry) registerAWSIntegrations() {
	// // AWS CloudTrail - commonly used for security auditing
	// // https://www.elastic.co/docs/current/integrations/aws/cloudtrail
	// //
	// // v2.0.0+: Added sqs:DeleteMessage as required (queue-based ingestion became default)
	// r.register("aws_cloudtrail", ">=2.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "cloudtrail:LookupEvents",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "cloudtrail:DescribeTrails",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "cloudtrail:GetTrailStatus",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "s3:GetObject",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "s3:ListBucket",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "sqs:ReceiveMessage",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "sqs:DeleteMessage",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })
	// // v1.x: Original permission set (SQS optional)
	// r.register("aws_cloudtrail", ">=1.0.0,<2.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "cloudtrail:LookupEvents",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "cloudtrail:DescribeTrails",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "cloudtrail:GetTrailStatus",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "s3:GetObject",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "s3:ListBucket",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "sqs:ReceiveMessage",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "sqs:DeleteMessage",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // AWS GuardDuty - threat detection service
	// r.register("aws_guardduty", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "guardduty:ListDetectors",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "guardduty:GetFindings",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "guardduty:ListFindings",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // AWS Security Hub - security findings aggregation
	// r.register("aws_securityhub", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "securityhub:GetFindings",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "securityhub:BatchGetSecurityControls",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "securityhub:DescribeHub",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 	},
	// })

	// // AWS S3 - storage access logs
	// r.register("aws_s3", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "s3:ListBucket",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "s3:GetObject",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "s3:GetBucketLocation",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 	},
	// })

	// // AWS EC2 - compute instance metrics
	// r.register("aws_ec2", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "ec2:DescribeInstances",
	// 			Required: true,
	// 			Method:   MethodDryRun,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "ec2:DescribeRegions",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "cloudwatch:GetMetricData",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // AWS VPC Flow Logs
	// r.register("aws_vpcflow", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "logs:FilterLogEvents",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "logs:DescribeLogGroups",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "logs:DescribeLogStreams",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "ec2:DescribeFlowLogs",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 	},
	// })

	// // AWS WAF - Web Application Firewall logs
	// r.register("aws_waf", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "wafv2:GetWebACL",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "wafv2:ListWebACLs",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "s3:GetObject",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "s3:ListBucket",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // AWS Route53 - DNS query logs
	// r.register("aws_route53", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "logs:FilterLogEvents",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "logs:DescribeLogGroups",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 		{
	// 			Action:   "route53:ListHostedZones",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 	},
	// })

	// // AWS ELB - Elastic Load Balancer access logs
	// r.register("aws_elb", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "s3:GetObject",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "s3:ListBucket",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "elasticloadbalancing:DescribeLoadBalancers",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 	},
	// })

	// // AWS CloudFront - CDN access logs
	// r.register("aws_cloudfront", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAWS,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "s3:GetObject",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "s3:ListBucket",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "cloudfront:ListDistributions",
	// 			Required: false,
	// 			Method:   MethodAPICall,
	// 			Category: "management",
	// 		},
	// 	},
	// })

	// AWS CSPM - Cloud Security Posture Management
	// Verifies that the SecurityAudit managed policy is attached to the assumed role.
	r.register("aws_cspm", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "arn:aws:iam::aws:policy/SecurityAudit",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "security_posture",
			},
		},
	})

	// AWS Asset Inventory - Cloud Asset Discovery
	// Verifies that the SecurityAudit managed policy is attached to the assumed role.
	r.register("aws_asset_inventory", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAWS,
		Permissions: []Permission{
			{
				Action:   "arn:aws:iam::aws:policy/SecurityAudit",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "asset_inventory",
			},
		},
	})
}

// registerAzureIntegrations registers all Azure-based integrations.
func (r *PermissionRegistry) registerAzureIntegrations() {
	// // Azure Activity Logs
	// r.register("azure_activitylogs", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAzure,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "Microsoft.Insights/eventtypes/values/Read",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // Azure Audit Logs
	// r.register("azure_auditlogs", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAzure,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "Microsoft.Insights/eventtypes/values/Read",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // Azure Blob Storage
	// r.register("azure_blob_storage", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderAzure,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "Microsoft.Storage/storageAccounts/blobServices/containers/read",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// Azure CSPM - Cloud Security Posture Management
	// Verifies that the Reader built-in role is assigned at subscription scope.
	r.register("azure_cspm", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAzure,
		Permissions: []Permission{
			{
				Action:   "Reader",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "security_posture",
			},
		},
	})

	// Azure Asset Inventory - Cloud Asset Discovery
	// Verifies that the Reader built-in role is assigned at subscription scope.
	r.register("azure_asset_inventory", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderAzure,
		Permissions: []Permission{
			{
				Action:   "Reader",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "asset_inventory",
			},
		},
	})
}

// registerGCPIntegrations registers all GCP-based integrations.
func (r *PermissionRegistry) registerGCPIntegrations() {
	// // GCP Audit Logs
	// r.register("gcp_audit", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderGCP,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "logging.logEntries.list",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // GCP Cloud Storage
	// r.register("gcp_storage", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderGCP,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "storage.objects.get",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 		{
	// 			Action:   "storage.objects.list",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// // GCP Pub/Sub
	// r.register("gcp_pubsub", ">=0.0.0", IntegrationPermissions{
	// 	Provider: verifier.ProviderGCP,
	// 	Permissions: []Permission{
	// 		{
	// 			Action:   "pubsub.subscriptions.consume",
	// 			Required: true,
	// 			Method:   MethodAPICall,
	// 			Category: "data_access",
	// 		},
	// 	},
	// })

	// GCP CSPM - Cloud Security Posture Management
	// Verifies that roles/cloudasset.viewer and roles/browser are bound to the
	// service account in the project's IAM policy.
	r.register("gcp_cspm", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderGCP,
		Permissions: []Permission{
			{
				Action:   "roles/cloudasset.viewer",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "security_posture",
			},
			{
				Action:   "roles/browser",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "security_posture",
			},
		},
	})

	// GCP Asset Inventory - Cloud Asset Discovery
	// Verifies that roles/cloudasset.viewer and roles/browser are bound to the
	// service account in the project's IAM policy.
	r.register("gcp_asset_inventory", ">=0.0.0", IntegrationPermissions{
		Provider: verifier.ProviderGCP,
		Permissions: []Permission{
			{
				Action:   "roles/cloudasset.viewer",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "asset_inventory",
			},
			{
				Action:   "roles/browser",
				Required: true,
				Method:   MethodPolicyAttachmentCheck,
				Category: "asset_inventory",
			},
		},
	})
}

// // registerOktaIntegrations is a placeholder for Okta-based integrations.
// // Okta entries are intentionally not registered until an Okta verifier
// // factory is implemented and wired in receiver.go. Registering them now
// // would cause VerifierNotInitialized errors at runtime.
// func (r *PermissionRegistry) registerOktaIntegrations() {
// }
