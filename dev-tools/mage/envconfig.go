// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"go/build"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// EnvConfig holds all configuration read from environment variables.
// Use GetConfig() to access the singleton instance after initialization.
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

	// DevBuild indicates whether this is a development build (from DEV env var)
	DevBuild bool

	// ExternalBuild indicates whether to use external artifact builds (from EXTERNAL env var)
	ExternalBuild bool

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
}

var (
	globalConfig     *EnvConfig
	globalConfigOnce sync.Once
	globalConfigErr  error
)

// GetConfig returns the singleton EnvConfig instance, loading it if necessary.
// This function is safe for concurrent use.
func GetConfig() (*EnvConfig, error) {
	globalConfigOnce.Do(func() {
		globalConfig, globalConfigErr = LoadConfig()
	})
	return globalConfig, globalConfigErr
}

// MustGetConfig returns the singleton EnvConfig instance, panicking on error.
func MustGetConfig() *EnvConfig {
	cfg, err := GetConfig()
	if err != nil {
		panic(fmt.Errorf("failed to load config: %w", err))
	}
	return cfg
}

// LoadConfig reads all configuration from environment variables and returns a new EnvConfig.
// This can be called multiple times to get fresh configuration, but GetConfig() should
// be preferred for normal use as it caches the result.
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

	return cfg, nil
}

// loadBuildConfig loads build-related configuration from environment variables.
func (c *EnvConfig) loadBuildConfig() error {
	c.Build.GOOS = build.Default.GOOS
	c.Build.GOARCH = build.Default.GOARCH
	c.Build.GOARM = envOr("GOARM", "")
	c.Build.CI = envOr("CI", "")

	var err error

	c.Build.Snapshot, err = parseBoolEnv("SNAPSHOT", false)
	if err != nil {
		return fmt.Errorf("failed to parse SNAPSHOT: %w", err)
	}

	c.Build.DevBuild, err = parseBoolEnv("DEV", false)
	if err != nil {
		return fmt.Errorf("failed to parse DEV: %w", err)
	}

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

	return nil
}

// loadBeatConfig loads Beat metadata configuration from environment variables.
func (c *EnvConfig) loadBeatConfig() {
	const defaultName = "elastic-agent"

	c.Beat.Name = envOr("BEAT_NAME", defaultName)
	c.Beat.ServiceName = envOr("BEAT_SERVICE_NAME", c.Beat.Name)
	c.Beat.IndexPrefix = envOr("BEAT_INDEX_PREFIX", c.Beat.Name)
	c.Beat.Description = envOr("BEAT_DESCRIPTION", "")
	c.Beat.Vendor = envOr("BEAT_VENDOR", "Elastic")
	c.Beat.License = envOr("BEAT_LICENSE", "Elastic License 2.0")
	c.Beat.URL = envOr("BEAT_URL", "https://www.elastic.co/beats/"+c.Beat.Name)
	c.Beat.User = envOr("BEAT_USER", "root")
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
