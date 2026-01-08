// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"fmt"
	"go/build"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/magefile/mage/sh"
)

const (
	DefaultName        = "elastic-agent"
	DefaultDescription = "Elastic Agent - single, unified way to add monitoring for logs, metrics, and other types of data to a host."
	DefaultLicense     = "Elastic License 2.0"
	DefaultVendor      = "Elastic"
	DefaultUser        = "root"
)

// configContextKey is the key used to store EnvConfig in context.
type configContextKey struct{}

// ConfigFromContext returns the EnvConfig from the context if present,
// otherwise loads a fresh config from environment variables. This is the preferred
// way to get configuration in mage targets that receive a context.
func ConfigFromContext(ctx context.Context) *EnvConfig {
	if cfg, ok := ctx.Value(configContextKey{}).(*EnvConfig); ok && cfg != nil {
		return cfg
	}
	return MustLoadConfig()
}

// ContextWithConfig returns a new context with the given EnvConfig stored in it.
// Use this to pass configuration to dependent mage targets via mg.CtxDeps.
func ContextWithConfig(ctx context.Context, cfg *EnvConfig) context.Context {
	return context.WithValue(ctx, configContextKey{}, cfg)
}

// EnvConfig holds all configuration read from environment variables.
// Use LoadConfig() or MustLoadConfig() to create a new instance, or
// ConfigFromContext() to get config from a context.
type EnvConfig struct {
	// Build configuration
	Build BuildConfig

	// Beat metadata configuration
	Beat BeatConfig

	// Test configuration
	Test TestConfig

	// CrossBuild configuration
	CrossBuild CrossBuildConfig

	// Packaging configuration
	Packaging PackagingConfig

	// IntegrationTest configuration
	IntegrationTest IntegrationTestConfig

	// Docker configuration
	Docker DockerConfig

	// Kubernetes configuration
	Kubernetes KubernetesConfig

	// DevMachine configuration
	DevMachine DevMachineConfig

	// Fmt configuration
	Fmt FmtConfig

	// PlatformFilters holds additional platform filters to apply.
	// These are applied after the base platform list is determined.
	PlatformFilters []string

	// SelectedPackageTypes overrides the package types from PACKAGES env var.
	// If nil, the env var value is used.
	SelectedPackageTypes []PackageType

	// SelectedDockerVariants overrides the docker variants from DOCKER_VARIANTS env var.
	// If nil, the env var value is used.
	SelectedDockerVariants []DockerVariant
}

// Clone returns a deep copy of the EnvConfig.
// Use this when you need to modify config without affecting other users.
func (c *EnvConfig) Clone() *EnvConfig {
	clone := *c
	// Deep copy slices
	if c.Test.Tags != nil {
		clone.Test.Tags = make([]string, len(c.Test.Tags))
		copy(clone.Test.Tags, c.Test.Tags)
	}
	if c.PlatformFilters != nil {
		clone.PlatformFilters = make([]string, len(c.PlatformFilters))
		copy(clone.PlatformFilters, c.PlatformFilters)
	}
	if c.SelectedPackageTypes != nil {
		clone.SelectedPackageTypes = make([]PackageType, len(c.SelectedPackageTypes))
		copy(clone.SelectedPackageTypes, c.SelectedPackageTypes)
	}
	if c.SelectedDockerVariants != nil {
		clone.SelectedDockerVariants = make([]DockerVariant, len(c.SelectedDockerVariants))
		copy(clone.SelectedDockerVariants, c.SelectedDockerVariants)
	}
	return &clone
}

// WithDevBuild returns a copy of the config with DevBuild set to the given value.
func (c *EnvConfig) WithDevBuild(enabled bool) *EnvConfig {
	clone := c.Clone()
	clone.Build.DevBuild = enabled
	return clone
}

// WithExternalBuild returns a copy of the config with ExternalBuild set to the given value.
func (c *EnvConfig) WithExternalBuild(enabled bool) *EnvConfig {
	clone := c.Clone()
	clone.Build.ExternalBuild = enabled
	return clone
}

// WithFIPSBuild returns a copy of the config with FIPSBuild set to the given value.
func (c *EnvConfig) WithFIPSBuild(enabled bool) *EnvConfig {
	clone := c.Clone()
	clone.Build.FIPSBuild = enabled
	return clone
}

// WithSnapshot returns a copy of the config with Snapshot set to the given value.
func (c *EnvConfig) WithSnapshot(enabled bool) *EnvConfig {
	clone := c.Clone()
	clone.Build.Snapshot = enabled
	return clone
}

// WithPlatformFilter returns a copy of the config with an additional platform filter.
func (c *EnvConfig) WithPlatformFilter(filter string) *EnvConfig {
	clone := c.Clone()
	clone.PlatformFilters = append(clone.PlatformFilters, filter)
	return clone
}

// WithPackageTypes returns a copy of the config with the specified package types.
func (c *EnvConfig) WithPackageTypes(types []PackageType) *EnvConfig {
	clone := c.Clone()
	clone.SelectedPackageTypes = types
	return clone
}

// WithDockerVariants returns a copy of the config with the specified docker variants.
func (c *EnvConfig) WithDockerVariants(variants []DockerVariant) *EnvConfig {
	clone := c.Clone()
	clone.SelectedDockerVariants = variants
	return clone
}

// WithPlatforms returns a copy of the config with the specified platforms string.
// This replaces any existing platform configuration.
func (c *EnvConfig) WithPlatforms(platforms string) *EnvConfig {
	clone := c.Clone()
	clone.CrossBuild.Platforms = platforms
	clone.PlatformFilters = nil // Clear filters when setting platforms explicitly
	return clone
}

// WithAddedPackageType returns a copy of the config with the specified package type added.
// If the package type is already selected, returns a clone with no changes.
func (c *EnvConfig) WithAddedPackageType(pkgType PackageType) *EnvConfig {
	clone := c.Clone()
	currentTypes := c.GetPackageTypes()
	for _, t := range currentTypes {
		if t == pkgType {
			return clone // already selected
		}
	}
	clone.SelectedPackageTypes = append(currentTypes, pkgType)
	return clone
}

// WithBeatVersion returns a copy of the config with the specified beat version.
func (c *EnvConfig) WithBeatVersion(version string) *EnvConfig {
	clone := c.Clone()
	clone.Build.BeatVersion = version
	clone.Build.BeatVersionSet = true
	return clone
}

// WithAgentCommitHashOverride returns a copy of the config with the specified commit hash override.
func (c *EnvConfig) WithAgentCommitHashOverride(hash string) *EnvConfig {
	clone := c.Clone()
	clone.Build.AgentCommitHashOverride = hash
	return clone
}

// WithAgentDropPath returns a copy of the config with the specified agent drop path.
func (c *EnvConfig) WithAgentDropPath(path string) *EnvConfig {
	clone := c.Clone()
	clone.Packaging.AgentDropPath = path
	return clone
}

// WithStackProvisioner returns a copy of the config with the specified stack provisioner.
func (c *EnvConfig) WithStackProvisioner(provisioner string) *EnvConfig {
	clone := c.Clone()
	clone.IntegrationTest.StackProvisioner = provisioner
	return clone
}

// WithTestGroups returns a copy of the config with the specified test groups.
func (c *EnvConfig) WithTestGroups(groups string) *EnvConfig {
	clone := c.Clone()
	clone.IntegrationTest.Groups = groups
	return clone
}

// WithAgentBuildDir returns a copy of the config with the specified agent build directory.
func (c *EnvConfig) WithAgentBuildDir(path string) *EnvConfig {
	clone := c.Clone()
	clone.IntegrationTest.AgentBuildDir = path
	return clone
}

// WithTestBinaryName returns a copy of the config with the specified test binary name.
func (c *EnvConfig) WithTestBinaryName(name string) *EnvConfig {
	clone := c.Clone()
	clone.IntegrationTest.BinaryName = name
	return clone
}

// BuildConfig contains build-related configuration.
type BuildConfig struct {
	// GOOS is the target operating system (from build.Default.GOOS)
	GOOS string

	// GOARCH is the target architecture (from build.Default.GOARCH)
	GOARCH string

	// GOARM is the ARM version for compilation (from GOARM env var)
	GOARM string

	// Snapshot indicates whether this is a snapshot build (from SNAPSHOT env var)
	Snapshot bool

	// SnapshotSet indicates whether SNAPSHOT env var was explicitly set
	SnapshotSet bool

	// DevBuild indicates whether this is a development build (from DEV env var)
	DevBuild bool

	// ExternalBuild indicates whether to use external artifact builds (from EXTERNAL env var)
	ExternalBuild bool

	// ExternalBuildSet indicates whether EXTERNAL env var was explicitly set
	ExternalBuildSet bool

	// FIPSBuild indicates whether to build FIPS-compliant binaries (from FIPS env var)
	FIPSBuild bool

	// VersionQualifier is the version qualifier suffix e.g., "rc1" (from VERSION_QUALIFIER env var)
	VersionQualifier string

	// VersionQualified indicates whether a version qualifier is set
	VersionQualified bool

	// CI indicates we're running in a CI environment (from CI env var)
	CI string

	// MaxParallel is the maximum number of parallel jobs (from MAX_PARALLEL env var)
	MaxParallel int

	// BeatVersion overrides the beat version (from BEAT_VERSION or set programmatically)
	BeatVersion string

	// BeatVersionSet indicates if BeatVersion was explicitly set (env or programmatic)
	BeatVersionSet bool

	// AgentCommitHashOverride overrides the commit hash for packaging (from AGENT_COMMIT_HASH_OVERRIDE or set programmatically)
	AgentCommitHashOverride string

	// commitHash is the commit hash of the current build. Can be overridden via the AGENT_COMMIT_HASH_OVERRIDE env var.
	// We lazy load this value, because inside crossbuild containers, fetching it can fail.
	commitHash string

	// GolangCrossBuild indicates we're inside a golang-crossbuild container (from GOLANG_CROSSBUILD env var)
	GolangCrossBuild bool

	// BeatGoVersion overrides the Go version (from BEAT_GO_VERSION env var)
	BeatGoVersion string

	// BeatGoVersionSet indicates if BeatGoVersion was explicitly set
	BeatGoVersionSet bool

	// BeatDocBranch overrides the documentation branch (from BEAT_DOC_BRANCH env var)
	BeatDocBranch string

	// BeatDocBranchSet indicates if BeatDocBranch was explicitly set
	BeatDocBranchSet bool
}

func (bc *BuildConfig) CommitHash() (string, error) {
	if bc.AgentCommitHashOverride != "" {
		return bc.AgentCommitHashOverride, nil
	}
	if bc.commitHash == "" {
		var err error
		bc.commitHash, err = sh.Output("git", "rev-parse", "HEAD")
		if err != nil {
			return "", fmt.Errorf("failed to get commit hash: %w", err)
		}
	}
	return bc.commitHash, nil
}

func (bc *BuildConfig) CommitHashShort() (string, error) {
	shortHash, err := bc.CommitHash()
	if err != nil {
		return "", err
	}
	if len(shortHash) > 6 {
		shortHash = shortHash[:6]
	}
	return shortHash, nil
}

// BeatConfig contains Beat metadata configuration.
type BeatConfig struct {
	// Name is the project name (from BEAT_NAME env var, default "elastic-agent")
	Name string

	// ServiceName is the service name (from BEAT_SERVICE_NAME env var, default BeatName)
	ServiceName string

	// IndexPrefix is the Elasticsearch index prefix (from BEAT_INDEX_PREFIX env var, default BeatName)
	IndexPrefix string

	// Description is the project description (from BEAT_DESCRIPTION env var)
	Description string

	// Vendor is the vendor name (from BEAT_VENDOR env var, default "Elastic")
	Vendor string

	// License is the license type (from BEAT_LICENSE env var, default "Elastic License 2.0")
	License string

	// URL is the project URL (from BEAT_URL env var)
	URL string

	// User is the default user for packages (from BEAT_USER env var, default "root")
	User string
}

// TestConfig contains test-related configuration.
type TestConfig struct {
	// RaceDetector enables the Go race detector (from RACE_DETECTOR env var)
	RaceDetector bool

	// Coverage enables code coverage profiling (from TEST_COVERAGE env var)
	Coverage bool

	// Tags is a list of build tags for tests (from TEST_TAGS env var)
	Tags []string
}

// CrossBuildConfig contains cross-build configuration.
type CrossBuildConfig struct {
	// Platforms is the comma-separated list of target platforms (from PLATFORMS env var)
	Platforms string

	// Packages is the comma-separated list of package types (from PACKAGES env var)
	Packages string

	// DockerVariants is the comma-separated list of Docker variants (from DOCKER_VARIANTS env var)
	DockerVariants string

	// MountModcache enables mounting $GOPATH/pkg/mod into crossbuild containers (from CROSSBUILD_MOUNT_MODCACHE env var)
	MountModcache bool

	// MountBuildCache enables mounting Go build cache into crossbuild containers (from CROSSBUILD_MOUNT_GOCACHE env var)
	MountBuildCache bool

	// BuildCacheVolumeName is the Docker volume name for the build cache
	BuildCacheVolumeName string

	// DevOS is the target OS for config generation (from DEV_OS env var, default "linux")
	DevOS string

	// DevArch is the target architecture for config generation (from DEV_ARCH env var, default "amd64")
	DevArch string
}

// PackagingConfig contains packaging-related configuration.
type PackagingConfig struct {
	// AgentPackageVersion overrides the package version (from AGENT_PACKAGE_VERSION env var)
	AgentPackageVersion string

	// ManifestURL is the location of manifest file for packaging (from MANIFEST_URL env var)
	ManifestURL string

	// PackagingFromManifest indicates whether to use manifest for packaging (derived from ManifestURL)
	PackagingFromManifest bool

	// UsePackageVersion enables reading version from .package-version file (from USE_PACKAGE_VERSION env var)
	UsePackageVersion bool

	// AgentDropPath is the path for dropping agent artifacts (from AGENT_DROP_PATH env var)
	AgentDropPath string

	// KeepArchive indicates whether to keep the archive after packaging (from KEEP_ARCHIVE env var)
	KeepArchive bool
}

// IntegrationTestConfig contains integration test related configuration.
type IntegrationTestConfig struct {
	// AgentVersion is the agent version for integration tests (from AGENT_VERSION env var)
	AgentVersion string

	// AgentStackVersion is the stack version for integration tests (from AGENT_STACK_VERSION env var)
	AgentStackVersion string

	// AgentBuildDir is the build directory for agent artifacts (from AGENT_BUILD_DIR env var)
	AgentBuildDir string

	// StackProvisioner specifies the stack provisioner to use (from STACK_PROVISIONER env var)
	// Valid values: "stateful", "serverless"
	StackProvisioner string

	// InstanceProvisioner specifies the instance provisioner to use (from INSTANCE_PROVISIONER env var)
	// Valid values: "ogc", "multipass", "kind"
	InstanceProvisioner string

	// ESSRegion is the ESS region for testing (from TEST_INTEG_AUTH_ESS_REGION env var)
	ESSRegion string

	// GCPDatacenter is the GCP datacenter for testing (from TEST_INTEG_AUTH_GCP_DATACENTER env var)
	GCPDatacenter string

	// GCPProject is the GCP project for testing (from TEST_INTEG_AUTH_GCP_PROJECT env var)
	GCPProject string

	// GCPEmailDomain is the expected email domain for GCP auth (from TEST_INTEG_AUTH_EMAIL_DOMAIN env var)
	GCPEmailDomain string

	// GCPServiceTokenFile is the path to GCP service token file (from TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE env var)
	GCPServiceTokenFile string

	// Platforms specifies the test platforms (from TEST_PLATFORMS env var)
	Platforms string

	// Packages specifies the test packages (from TEST_PACKAGES env var)
	Packages string

	// PackagesDefined indicates whether TEST_PACKAGES was explicitly set
	PackagesDefined bool

	// Groups specifies the test groups (from TEST_GROUPS env var)
	Groups string

	// DefinePrefix is the test define prefix (from TEST_DEFINE_PREFIX env var)
	DefinePrefix string

	// DefineTests specifies the tests to run (from TEST_DEFINE_TESTS env var)
	DefineTests string

	// BinaryName is the binary name for testing (from TEST_BINARY_NAME env var)
	BinaryName string

	// RepoPath is the repository path for testing (from TEST_INTEG_REPO_PATH env var)
	RepoPath string

	// TimestampEnabled enables timestamps in test output (from TEST_INTEG_TIMESTAMP env var)
	TimestampEnabled bool

	// RunUntilFailure runs tests until a failure occurs (from TEST_RUN_UNTIL_FAILURE env var)
	RunUntilFailure bool

	// CleanOnExit cleans up on exit (from TEST_INTEG_CLEAN_ON_EXIT env var)
	CleanOnExit bool

	// LongRunning enables long running tests (from TEST_LONG_RUNNING env var)
	LongRunning string

	// LongTestRuntime specifies the runtime for long tests (from LONG_TEST_RUNTIME env var)
	LongTestRuntime string

	// CollectDiag enables diagnostic collection (from AGENT_COLLECT_DIAG env var)
	CollectDiag string

	// KeepInstalled keeps the agent installed after tests (from AGENT_KEEP_INSTALLED env var)
	KeepInstalled string

	// BuildAgent indicates whether to build the agent before tests (from BUILD_AGENT env var)
	BuildAgent bool

	// GoTestFlags contains additional flags for go test (from GOTEST_FLAGS env var)
	GoTestFlags string

	// TestEnvironment enables/disables the test environment (from TEST_ENVIRONMENT env var)
	TestEnvironment string

	// TestEnvironmentSet indicates whether TEST_ENVIRONMENT was explicitly set
	TestEnvironmentSet bool
}

// DockerConfig contains Docker-related configuration.
type DockerConfig struct {
	// ImportSource overrides the docker import source (from DOCKER_IMPORT_SOURCE env var)
	ImportSource string

	// CustomImageTag overrides the docker image tag (from CUSTOM_IMAGE_TAG env var)
	CustomImageTag string

	// CIElasticAgentDockerImage overrides the CI docker image (from CI_ELASTIC_AGENT_DOCKER_IMAGE env var)
	CIElasticAgentDockerImage string

	// NoCache disables docker build cache (from DOCKER_NOCACHE env var)
	NoCache bool

	// ForcePull forces docker to pull images (from DOCKER_PULL env var)
	ForcePull bool

	// WindowsNpcap enables Windows NPCAP support (from WINDOWS_NPCAP env var)
	WindowsNpcap bool
}

// KubernetesConfig contains Kubernetes-related configuration.
type KubernetesConfig struct {
	// K8sVersion is the Kubernetes version (from K8S_VERSION env var)
	K8sVersion string

	// KindSkipDelete skips Kind cluster deletion (from KIND_SKIP_DELETE env var)
	KindSkipDelete bool
}

// DevMachineConfig contains configuration for dev machine provisioning.
type DevMachineConfig struct {
	// MachineImage is the GCP machine image to use (from MACHINE_IMAGE env var)
	// Defaults to "family/platform-ingest-elastic-agent-ubuntu-2204"
	MachineImage string

	// Zone is the GCP zone to use (from ZONE env var)
	// Defaults to "us-central1-a"
	Zone string
}

const (
	// DefaultDevMachineImage is the default GCP machine image for dev machines.
	DefaultDevMachineImage = "family/platform-ingest-elastic-agent-ubuntu-2204"
	// DefaultDevMachineZone is the default GCP zone for dev machines.
	DefaultDevMachineZone = "us-central1-a"
)

// FmtConfig contains configuration for formatting tools.
type FmtConfig struct {
	// CheckHeadersDisabled disables license header checking (from CHECK_HEADERS_DISABLED env var)
	CheckHeadersDisabled bool
}

// MustLoadConfig reads all configuration from environment variables and returns a new EnvConfig.
// It panics if config loading fails. Use this when you need config but don't have a context.
func MustLoadConfig() *EnvConfig {
	cfg, err := LoadConfig()
	if err != nil {
		panic(fmt.Errorf("failed to load config: %w", err))
	}
	return cfg
}

// LoadConfig reads all configuration from environment variables and returns a new EnvConfig.
// Each call returns a fresh config loaded from the current environment.
func LoadConfig() (*EnvConfig, error) {
	cfg := &EnvConfig{}

	if err := cfg.loadBuildConfig(); err != nil {
		return nil, fmt.Errorf("loading build config: %w", err)
	}

	cfg.loadBeatConfig()

	if err := cfg.loadTestConfig(); err != nil {
		return nil, fmt.Errorf("loading test config: %w", err)
	}

	cfg.loadCrossBuildConfig()
	cfg.loadPackagingConfig()
	cfg.loadIntegrationTestConfig()
	cfg.loadDockerConfig()
	cfg.loadKubernetesConfig()
	cfg.loadDevMachineConfig()
	cfg.loadFmtConfig()

	return cfg, nil
}

// loadBuildConfig loads build-related configuration from environment variables.
func (c *EnvConfig) loadBuildConfig() error {
	c.Build.GOOS = build.Default.GOOS
	c.Build.GOARCH = build.Default.GOARCH
	c.Build.GOARM = envOr("GOARM", "")
	c.Build.CI = envOr("CI", "")

	var err error

	_, c.Build.SnapshotSet = os.LookupEnv("SNAPSHOT")
	c.Build.Snapshot, err = parseBoolEnv("SNAPSHOT", false)
	if err != nil {
		return fmt.Errorf("failed to parse SNAPSHOT: %w", err)
	}

	c.Build.DevBuild, err = parseBoolEnv("DEV", false)
	if err != nil {
		return fmt.Errorf("failed to parse DEV: %w", err)
	}

	_, c.Build.ExternalBuildSet = os.LookupEnv("EXTERNAL")
	c.Build.ExternalBuild, err = parseBoolEnv("EXTERNAL", false)
	if err != nil {
		return fmt.Errorf("failed to parse EXTERNAL: %w", err)
	}

	c.Build.FIPSBuild, err = parseBoolEnv("FIPS", false)
	if err != nil {
		return fmt.Errorf("failed to parse FIPS: %w", err)
	}

	c.Build.VersionQualifier, c.Build.VersionQualified = os.LookupEnv("VERSION_QUALIFIER")

	// Parse MAX_PARALLEL with fallback to CPU count
	if maxParallel := os.Getenv("MAX_PARALLEL"); maxParallel != "" {
		if num, err := strconv.Atoi(maxParallel); err == nil && num > 0 {
			c.Build.MaxParallel = num
		}
	}
	if c.Build.MaxParallel == 0 {
		c.Build.MaxParallel = runtime.NumCPU()
	}

	// Read BEAT_VERSION override
	c.Build.BeatVersion, c.Build.BeatVersionSet = os.LookupEnv("BEAT_VERSION")

	// Read AGENT_COMMIT_HASH_OVERRIDE
	c.Build.AgentCommitHashOverride = envOr("AGENT_COMMIT_HASH_OVERRIDE", "")

	// Read GOLANG_CROSSBUILD
	c.Build.GolangCrossBuild = envOr("GOLANG_CROSSBUILD", "") == "1"

	// Read BEAT_GO_VERSION override
	c.Build.BeatGoVersion, c.Build.BeatGoVersionSet = os.LookupEnv("BEAT_GO_VERSION")

	// Read BEAT_DOC_BRANCH override
	c.Build.BeatDocBranch, c.Build.BeatDocBranchSet = os.LookupEnv("BEAT_DOC_BRANCH")

	return nil
}

// loadBeatConfig loads Beat metadata configuration from environment variables.
func (c *EnvConfig) loadBeatConfig() {
	c.Beat.Name = envOr("BEAT_NAME", DefaultName)
	c.Beat.ServiceName = envOr("BEAT_SERVICE_NAME", c.Beat.Name)
	c.Beat.IndexPrefix = envOr("BEAT_INDEX_PREFIX", c.Beat.Name)
	c.Beat.Description = envOr("BEAT_DESCRIPTION", DefaultDescription)
	c.Beat.Vendor = envOr("BEAT_VENDOR", DefaultVendor)
	c.Beat.License = envOr("BEAT_LICENSE", DefaultLicense)
	c.Beat.URL = envOr("BEAT_URL", "https://www.elastic.co/beats/"+c.Beat.Name)
	c.Beat.User = envOr("BEAT_USER", DefaultUser)
}

// loadTestConfig loads test-related configuration from environment variables.
func (c *EnvConfig) loadTestConfig() error {
	var err error

	c.Test.RaceDetector, err = parseBoolEnv("RACE_DETECTOR", false)
	if err != nil {
		return fmt.Errorf("failed to parse RACE_DETECTOR: %w", err)
	}

	c.Test.Coverage, err = parseBoolEnv("TEST_COVERAGE", false)
	if err != nil {
		return fmt.Errorf("failed to parse TEST_COVERAGE: %w", err)
	}

	// Parse TEST_TAGS
	if tags := os.Getenv("TEST_TAGS"); tags != "" {
		c.Test.Tags = strings.Split(strings.Trim(tags, ", "), ",")
	}

	return nil
}

// loadCrossBuildConfig loads cross-build configuration from environment variables.
func (c *EnvConfig) loadCrossBuildConfig() {
	c.CrossBuild.Platforms = envOr("PLATFORMS", "")
	c.CrossBuild.Packages = envOr("PACKAGES", "")
	c.CrossBuild.DockerVariants = envOr("DOCKER_VARIANTS", "")
	c.CrossBuild.MountModcache = envOr("CROSSBUILD_MOUNT_MODCACHE", "true") == "true"
	c.CrossBuild.MountBuildCache = envOr("CROSSBUILD_MOUNT_GOCACHE", "true") == "true"
	c.CrossBuild.BuildCacheVolumeName = "elastic-agent-crossbuild-build-cache"
	c.CrossBuild.DevOS = envOr("DEV_OS", "linux")
	c.CrossBuild.DevArch = envOr("DEV_ARCH", "amd64")
}

// loadPackagingConfig loads packaging-related configuration from environment variables.
func (c *EnvConfig) loadPackagingConfig() {
	c.Packaging.AgentPackageVersion = envOr("AGENT_PACKAGE_VERSION", "")
	c.Packaging.ManifestURL = envOr("MANIFEST_URL", "")
	c.Packaging.PackagingFromManifest = c.Packaging.ManifestURL != ""
	c.Packaging.UsePackageVersion = envOr("USE_PACKAGE_VERSION", "") == "true"
	c.Packaging.AgentDropPath = envOr("AGENT_DROP_PATH", "")
	c.Packaging.KeepArchive = envOr("KEEP_ARCHIVE", "") != ""
}

// loadIntegrationTestConfig loads integration test configuration from environment variables.
func (c *EnvConfig) loadIntegrationTestConfig() {
	c.IntegrationTest.AgentVersion = envOr("AGENT_VERSION", "")
	c.IntegrationTest.AgentStackVersion = envOr("AGENT_STACK_VERSION", "")
	c.IntegrationTest.AgentBuildDir = envOr("AGENT_BUILD_DIR", "")
	c.IntegrationTest.StackProvisioner = envOr("STACK_PROVISIONER", "")
	c.IntegrationTest.InstanceProvisioner = envOr("INSTANCE_PROVISIONER", "")
	c.IntegrationTest.ESSRegion = envOr("TEST_INTEG_AUTH_ESS_REGION", "")
	c.IntegrationTest.GCPDatacenter = envOr("TEST_INTEG_AUTH_GCP_DATACENTER", "")
	c.IntegrationTest.GCPProject = envOr("TEST_INTEG_AUTH_GCP_PROJECT", "")
	c.IntegrationTest.GCPEmailDomain = envOr("TEST_INTEG_AUTH_EMAIL_DOMAIN", "")
	c.IntegrationTest.GCPServiceTokenFile = envOr("TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE", "")
	c.IntegrationTest.Platforms = envOr("TEST_PLATFORMS", "")
	_, c.IntegrationTest.PackagesDefined = os.LookupEnv("TEST_PACKAGES")
	c.IntegrationTest.Packages = envOr("TEST_PACKAGES", "")
	c.IntegrationTest.Groups = envOr("TEST_GROUPS", "")
	c.IntegrationTest.DefinePrefix = envOr("TEST_DEFINE_PREFIX", "")
	c.IntegrationTest.DefineTests = envOr("TEST_DEFINE_TESTS", "")
	c.IntegrationTest.BinaryName = envOr("TEST_BINARY_NAME", "")
	c.IntegrationTest.RepoPath = envOr("TEST_INTEG_REPO_PATH", "")
	c.IntegrationTest.TimestampEnabled = envOr("TEST_INTEG_TIMESTAMP", "") == "true"
	c.IntegrationTest.RunUntilFailure = envOr("TEST_RUN_UNTIL_FAILURE", "") == "true"
	c.IntegrationTest.CleanOnExit = envOr("TEST_INTEG_CLEAN_ON_EXIT", "") != "false"
	c.IntegrationTest.LongRunning = envOr("TEST_LONG_RUNNING", "")
	c.IntegrationTest.LongTestRuntime = envOr("LONG_TEST_RUNTIME", "")
	c.IntegrationTest.CollectDiag = envOr("AGENT_COLLECT_DIAG", "")
	c.IntegrationTest.KeepInstalled = envOr("AGENT_KEEP_INSTALLED", "")
	c.IntegrationTest.BuildAgent = envOr("BUILD_AGENT", "") == "true"
	c.IntegrationTest.GoTestFlags = envOr("GOTEST_FLAGS", "")
	c.IntegrationTest.TestEnvironment, c.IntegrationTest.TestEnvironmentSet = os.LookupEnv("TEST_ENVIRONMENT")
}

// loadDockerConfig loads Docker-related configuration from environment variables.
func (c *EnvConfig) loadDockerConfig() {
	c.Docker.ImportSource = envOr("DOCKER_IMPORT_SOURCE", "")
	c.Docker.CustomImageTag = envOr("CUSTOM_IMAGE_TAG", "")
	c.Docker.CIElasticAgentDockerImage = envOr("CI_ELASTIC_AGENT_DOCKER_IMAGE", "")
	_, c.Docker.NoCache = os.LookupEnv("DOCKER_NOCACHE")
	_, c.Docker.ForcePull = os.LookupEnv("DOCKER_PULL")
	c.Docker.WindowsNpcap = envOr("WINDOWS_NPCAP", "") == "true"
}

// loadKubernetesConfig loads Kubernetes-related configuration from environment variables.
func (c *EnvConfig) loadKubernetesConfig() {
	c.Kubernetes.K8sVersion = envOr("K8S_VERSION", "")
	c.Kubernetes.KindSkipDelete = envOr("KIND_SKIP_DELETE", "") == "true"
}

// loadDevMachineConfig loads dev machine provisioning configuration from environment variables.
func (c *EnvConfig) loadDevMachineConfig() {
	c.DevMachine.MachineImage = envOr("MACHINE_IMAGE", DefaultDevMachineImage)
	c.DevMachine.Zone = envOr("ZONE", DefaultDevMachineZone)
}

// loadFmtConfig loads formatting tools configuration from environment variables.
func (c *EnvConfig) loadFmtConfig() {
	_, c.Fmt.CheckHeadersDisabled = os.LookupEnv("CHECK_HEADERS_DISABLED")
}

// envOr returns the value of the specified environment variable if it is
// non-empty. Otherwise it returns def.
func envOr(name, def string) string {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	return s
}

// parseBoolEnv parses a boolean environment variable with a default value.
func parseBoolEnv(name string, def bool) (bool, error) {
	s := os.Getenv(name)
	if s == "" {
		return def, nil
	}
	return strconv.ParseBool(s)
}

// BinaryExt returns the appropriate binary extension for the configured GOOS.
func (c *EnvConfig) BinaryExt() string {
	if c.Build.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// Platform returns platform attributes for the current build configuration.
func (c *EnvConfig) Platform() PlatformAttributes {
	return MakePlatformAttributes(c.Build.GOOS, c.Build.GOARCH, c.Build.GOARM)
}

// TestTagsWithFIPS returns the test tags, including FIPS-related tags if FIPSBuild is enabled.
func (c *EnvConfig) TestTagsWithFIPS() []string {
	tags := make([]string, len(c.Test.Tags))
	copy(tags, c.Test.Tags)
	if c.Build.FIPSBuild {
		tags = append(tags, "requirefips", "ms_tls13kdf")
	}
	return tags
}

// GetPlatforms returns the parsed platform list from PLATFORMS env var.
// If PLATFORMS is empty, returns the default platform list.
// Platform filters from the config's PlatformFilters are applied to the result.
// Note: linux/386 and windows/386 are always filtered out as they are not supported.
func (c *EnvConfig) GetPlatforms() BuildPlatformList {
	var platforms BuildPlatformList
	if c.CrossBuild.Platforms != "" {
		platforms = NewPlatformList(c.CrossBuild.Platforms)
	} else {
		platforms = BuildPlatforms.Defaults()
	}

	// Filter out unsupported platforms
	platforms = platforms.Filter("!linux/386")
	platforms = platforms.Filter("!windows/386")

	// Apply platform filters from config
	for _, filter := range c.PlatformFilters {
		platforms = platforms.Filter(filter)
	}

	return platforms
}

// GetPackageTypes returns the package types to use.
// If SelectedPackageTypes is set in the config, returns that.
// Otherwise parses from PACKAGES env var.
// If PACKAGES is empty, returns nil (meaning all package types are selected).
func (c *EnvConfig) GetPackageTypes() []PackageType {
	// Check config override first
	if c.SelectedPackageTypes != nil {
		return c.SelectedPackageTypes
	}
	// Fall back to env var
	if c.CrossBuild.Packages == "" {
		return nil
	}
	var types []PackageType
	for _, pkgtype := range strings.Split(c.CrossBuild.Packages, ",") {
		var p PackageType
		if err := p.UnmarshalText([]byte(pkgtype)); err == nil {
			types = append(types, p)
		}
	}
	return types
}

// GetDockerVariants returns the docker variants to use.
// If SelectedDockerVariants is set in the config, returns that.
// Otherwise parses from DOCKER_VARIANTS env var.
// If DOCKER_VARIANTS is empty, returns nil (meaning all variants are selected).
func (c *EnvConfig) GetDockerVariants() []DockerVariant {
	// Check config override first
	if c.SelectedDockerVariants != nil {
		return c.SelectedDockerVariants
	}
	// Fall back to env var
	if c.CrossBuild.DockerVariants == "" {
		return nil
	}
	var variants []DockerVariant
	for _, variant := range strings.Split(c.CrossBuild.DockerVariants, ",") {
		var v DockerVariant
		if err := v.UnmarshalText([]byte(variant)); err == nil {
			variants = append(variants, v)
		}
	}
	return variants
}

// IsPackageTypeSelected returns true if SelectedPackageTypes is empty or if
// pkgType is present on SelectedPackageTypes. It returns false otherwise.
func (c *EnvConfig) IsPackageTypeSelected(pkgType PackageType) bool {
	selectedTypes := c.GetPackageTypes()
	if len(selectedTypes) == 0 {
		return true
	}

	for _, t := range selectedTypes {
		if t == pkgType {
			return true
		}
	}
	return false
}

// IsDockerVariantSelected returns true if SelectedDockerVariants is empty or if
// docVariant is present on SelectedDockerVariants. It returns false otherwise.
func (c *EnvConfig) IsDockerVariantSelected(docVariant DockerVariant) bool {
	selectedVariants := c.GetDockerVariants()
	if len(selectedVariants) == 0 {
		return true
	}

	for _, v := range selectedVariants {
		if v == docVariant {
			return true
		}
	}
	return false
}
