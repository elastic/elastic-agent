// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline

// Image constants for VM images used in Buildkite pipelines.
// These values are managed by updatecli and should not be changed manually.
//
// The image names follow the pattern: platform-ingest-elastic-agent-{os}-{version}
// where version is a timestamp-based identifier.
const (
	// Ubuntu images
	ImageUbuntu2204X86 = "platform-ingest-elastic-agent-ubuntu-2204-1762801856"
	ImageUbuntu2204ARM = "platform-ingest-elastic-agent-ubuntu-2204-aarch64-1762801856"
	ImageUbuntu2404X86 = "platform-ingest-elastic-agent-ubuntu-2404-1762801856"
	ImageUbuntu2404ARM = "platform-ingest-elastic-agent-ubuntu-2404-aarch64-1762801856"

	// Windows images
	ImageWin2016 = "platform-ingest-elastic-agent-windows-2016-1762801856"
	ImageWin2022 = "platform-ingest-elastic-agent-windows-2022-1762801856"
	ImageWin2025 = "platform-ingest-elastic-agent-windows-2025-1762801856"
	ImageWin10   = "platform-ingest-elastic-agent-windows-10-1764775167"
	ImageWin11   = "platform-ingest-elastic-agent-windows-11-1764775167"

	// RHEL images
	ImageRHEL8  = "platform-ingest-elastic-agent-rhel-8-1762801856"
	ImageRHEL10 = "platform-ingest-elastic-agent-rhel-10-1762801856"

	// Debian images
	ImageDebian11 = "platform-ingest-elastic-agent-debian-11-1762801856"
	ImageDebian13 = "platform-ingest-elastic-agent-debian-13-1762801856"

	// FIPS images
	ImageUbuntuX86FIPS   = "platform-ingest-elastic-agent-ubuntu-2204-fips-1762801856"
	ImageUbuntuARM64FIPS = "platform-ingest-elastic-agent-ubuntu-2204-fips-aarch64-1762801856"
)

// ImageEnvVars returns a map of environment variable names to image values.
// This is useful for pipelines that reference images via environment variables
// (e.g., ${IMAGE_UBUNTU_2204_X86_64}).
func ImageEnvVars() map[string]string {
	return map[string]string{
		"IMAGE_UBUNTU_2204_X86_64": ImageUbuntu2204X86,
		"IMAGE_UBUNTU_2204_ARM_64": ImageUbuntu2204ARM,
		"IMAGE_UBUNTU_2404_X86_64": ImageUbuntu2404X86,
		"IMAGE_UBUNTU_2404_ARM_64": ImageUbuntu2404ARM,
		"IMAGE_WIN_2016":           ImageWin2016,
		"IMAGE_WIN_2022":           ImageWin2022,
		"IMAGE_WIN_2025":           ImageWin2025,
		"IMAGE_WIN_10":             ImageWin10,
		"IMAGE_WIN_11":             ImageWin11,
		"IMAGE_RHEL_8":             ImageRHEL8,
		"IMAGE_RHEL_10":            ImageRHEL10,
		"IMAGE_DEBIAN_11":          ImageDebian11,
		"IMAGE_DEBIAN_13":          ImageDebian13,
	}
}

// Common machine types for GCP and AWS agents.
const (
	// GCP machine types
	MachineTypeN2Standard4  = "n2-standard-4"
	MachineTypeN2Standard8  = "n2-standard-8"
	MachineTypeN2Standard16 = "n2-standard-16"
	MachineTypeC2Standard16 = "c2-standard-16"

	// AWS instance types
	InstanceTypeM6gXLarge  = "m6g.xlarge"
	InstanceTypeM6g2XLarge = "m6g.2xlarge"
	InstanceTypeC6gXLarge  = "c6g.xlarge"
	InstanceTypeC6g2XLarge = "c6g.2xlarge"
	InstanceTypeC6g4XLarge = "c6g.4xlarge"
	InstanceTypeT4g2XLarge = "t4g.2xlarge"
)

// Common disk sizes in GB.
const (
	DiskSize80GB  = 80
	DiskSize200GB = 200
	DiskSize400GB = 400
)

// Common vault paths.
const (
	VaultPathGCP                = "kv/ci-shared/observability-ingest/cloud/gcp"
	VaultPathDockerRegistry     = "kv/ci-shared/platform-ingest/elastic_docker_registry"
	VaultPathECKeyProd          = "kv/ci-shared/platform-ingest/platform-ingest-ec-prod"
	VaultPathECKeyStagingGov    = "kv/ci-shared/platform-ingest/platform-ingest-ec-staging-gov"
	VaultPathBuildkiteAnalytics = "kv/ci-shared/platform-ingest/buildkite_analytics_token"
)
