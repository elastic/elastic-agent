// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	cfg, err := LoadSettings()
	require.NoError(t, err)
	bp, err := BeatQualifiedVersion(cfg)
	assert.NoError(t, err)
	_ = bp
}

func TestAgentPackageVersion(t *testing.T) {
	t.Run("agent package version without env var", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)
		expectedPkgVersion, err := BeatQualifiedVersion(cfg)
		require.NoError(t, err)
		actualPkgVersion, err := AgentPackageVersion(cfg)
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, actualPkgVersion)
	})

	t.Run("agent package version env var set", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)
		expectedPkgVersion := "1.2.3-specialrelease+abcdef"
		cfg.Packaging.AgentPackageVersion = expectedPkgVersion
		actualPkgVersion, err := AgentPackageVersion(cfg)
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, actualPkgVersion)
	})

	t.Run("agent package version function must be mapped", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)
		cfg.Packaging.AgentPackageVersion = "1.2.3-specialrelease+abcdef"
		funcMap := FuncMap(cfg)
		assert.Contains(t, funcMap, agentPackageVersionMappedFunc)
		require.IsType(t, funcMap[agentPackageVersionMappedFunc], func() (string, error) { return "", nil })
		mappedFuncPkgVersion, err := funcMap[agentPackageVersionMappedFunc].(func() (string, error))()
		require.NoError(t, err)
		expectedPkgVersion, err := AgentPackageVersion(cfg)
		require.NoError(t, err)
		assert.Equal(t, expectedPkgVersion, mappedFuncPkgVersion)
	})
}

func TestSettingsClone(t *testing.T) {
	t.Run("clone creates independent copy", func(t *testing.T) {
		original := DefaultSettings()
		original.Build.DevBuild = true
		original.Test.Tags = []string{"tag1", "tag2"}
		original.PlatformFilters = []string{"linux/amd64"}
		original.SelectedPackageTypes = []PackageType{TarGz, Zip}
		original.SelectedDockerVariants = []DockerVariant{Basic, Cloud}

		clone := original.Clone()

		// Verify values are copied
		assert.Equal(t, original.Build.DevBuild, clone.Build.DevBuild)
		assert.Equal(t, original.Test.Tags, clone.Test.Tags)
		assert.Equal(t, original.PlatformFilters, clone.PlatformFilters)
		assert.Equal(t, original.SelectedPackageTypes, clone.SelectedPackageTypes)
		assert.Equal(t, original.SelectedDockerVariants, clone.SelectedDockerVariants)

		// Modify clone and verify original is unchanged
		clone.Build.DevBuild = false
		clone.Test.Tags[0] = "modified"
		clone.PlatformFilters[0] = "windows/amd64"
		clone.SelectedPackageTypes[0] = RPM
		clone.SelectedDockerVariants[0] = Complete

		assert.True(t, original.Build.DevBuild)
		assert.Equal(t, "tag1", original.Test.Tags[0])
		assert.Equal(t, "linux/amd64", original.PlatformFilters[0])
		assert.Equal(t, TarGz, original.SelectedPackageTypes[0])
		assert.Equal(t, Basic, int(original.SelectedDockerVariants[0]))
	})

	t.Run("clone handles nil slices", func(t *testing.T) {
		original := DefaultSettings()
		original.Test.Tags = nil
		original.PlatformFilters = nil
		original.SelectedPackageTypes = nil
		original.SelectedDockerVariants = nil

		clone := original.Clone()

		assert.Nil(t, clone.Test.Tags)
		assert.Nil(t, clone.PlatformFilters)
		assert.Nil(t, clone.SelectedPackageTypes)
		assert.Nil(t, clone.SelectedDockerVariants)
	})
}

func TestSettingsWithMethods(t *testing.T) {
	t.Run("WithDevBuild", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithDevBuild(true)

		assert.True(t, modified.Build.DevBuild)
		assert.False(t, original.Build.DevBuild) // original unchanged
	})

	t.Run("WithExternalBuild", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithExternalBuild(true)

		assert.True(t, modified.Build.ExternalBuild)
		assert.False(t, original.Build.ExternalBuild)
	})

	t.Run("WithFIPSBuild", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithFIPSBuild(true)

		assert.True(t, modified.Build.FIPSBuild)
		assert.False(t, original.Build.FIPSBuild)
	})

	t.Run("WithSnapshot", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithSnapshot(true)

		assert.True(t, modified.Build.Snapshot)
		assert.False(t, original.Build.Snapshot)
	})

	t.Run("WithPlatformFilter", func(t *testing.T) {
		original := DefaultSettings()
		original.PlatformFilters = []string{"linux/amd64"}

		modified := original.WithPlatformFilter("darwin/arm64")

		assert.Equal(t, []string{"linux/amd64", "darwin/arm64"}, modified.PlatformFilters)
		assert.Equal(t, []string{"linux/amd64"}, original.PlatformFilters)
	})

	t.Run("WithPackageTypes", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithPackageTypes([]PackageType{TarGz, Zip})

		assert.Equal(t, []PackageType{TarGz, Zip}, modified.SelectedPackageTypes)
		assert.Nil(t, original.SelectedPackageTypes)
	})

	t.Run("WithDockerVariants", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithDockerVariants([]DockerVariant{Basic, Cloud})

		assert.Equal(t, []DockerVariant{Basic, Cloud}, modified.SelectedDockerVariants)
		assert.Nil(t, original.SelectedDockerVariants)
	})

	t.Run("WithPlatforms", func(t *testing.T) {
		original := DefaultSettings()
		original.PlatformFilters = []string{"!windows"}

		modified := original.WithPlatforms("linux/amd64,darwin/arm64")

		assert.Equal(t, "linux/amd64,darwin/arm64", modified.CrossBuild.Platforms)
		assert.Nil(t, modified.PlatformFilters) // filters cleared
	})

	t.Run("WithAddedPackageType", func(t *testing.T) {
		original := DefaultSettings()
		original.SelectedPackageTypes = []PackageType{TarGz}

		modified := original.WithAddedPackageType(Zip)

		assert.Equal(t, []PackageType{TarGz, Zip}, modified.SelectedPackageTypes)
		assert.Equal(t, []PackageType{TarGz}, original.SelectedPackageTypes)
	})

	t.Run("WithAddedPackageType does not duplicate", func(t *testing.T) {
		original := DefaultSettings()
		original.SelectedPackageTypes = []PackageType{TarGz, Zip}

		modified := original.WithAddedPackageType(TarGz)

		assert.Equal(t, []PackageType{TarGz, Zip}, modified.SelectedPackageTypes)
	})

	t.Run("WithBeatVersion", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithBeatVersion("1.2.3")

		assert.Equal(t, "1.2.3", modified.Build.BeatVersion)
		assert.Empty(t, original.Build.BeatVersion)
	})

	t.Run("WithAgentCommitHashOverride", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithAgentCommitHashOverride("abc123")

		assert.Equal(t, "abc123", modified.Build.AgentCommitHashOverride)
		assert.Empty(t, original.Build.AgentCommitHashOverride)
	})

	t.Run("WithAgentDropPath", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithAgentDropPath("/path/to/drop")

		assert.Equal(t, "/path/to/drop", modified.Packaging.AgentDropPath)
		assert.Empty(t, original.Packaging.AgentDropPath)
	})

	t.Run("WithStackProvisioner", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithStackProvisioner("serverless")

		assert.Equal(t, "serverless", modified.IntegrationTest.StackProvisioner)
		assert.Empty(t, original.IntegrationTest.StackProvisioner)
	})

	t.Run("WithTestGroups", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithTestGroups("group1,group2")

		assert.Equal(t, "group1,group2", modified.IntegrationTest.Groups)
		assert.Empty(t, original.IntegrationTest.Groups)
	})

	t.Run("WithAgentBuildDir", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithAgentBuildDir("/build/dir")

		assert.Equal(t, "/build/dir", modified.IntegrationTest.AgentBuildDir)
		assert.Empty(t, original.IntegrationTest.AgentBuildDir)
	})

	t.Run("WithTestBinaryName", func(t *testing.T) {
		original := DefaultSettings()

		modified := original.WithTestBinaryName("test-binary")

		assert.Equal(t, "test-binary", modified.IntegrationTest.BinaryName)
		assert.Empty(t, original.IntegrationTest.BinaryName)
	})
}

func TestSettingsBinaryExt(t *testing.T) {
	t.Run("returns .exe for windows", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.GOOS = "windows"
		assert.Equal(t, ".exe", s.BinaryExt())
	})

	t.Run("returns empty string for linux", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.GOOS = "linux"
		assert.Equal(t, "", s.BinaryExt())
	})

	t.Run("returns empty string for darwin", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.GOOS = "darwin"
		assert.Equal(t, "", s.BinaryExt())
	})
}

func TestSettingsPlatform(t *testing.T) {
	s := DefaultSettings()
	s.Build.GOOS = "linux"
	s.Build.GOARCH = "amd64"
	s.Build.GOARM = ""

	platform := s.Platform()

	assert.Equal(t, "linux", platform.GOOS)
	assert.Equal(t, "amd64", platform.Arch)
}

func TestSettingsTestTagsWithFIPS(t *testing.T) {
	t.Run("returns original tags when FIPS disabled", func(t *testing.T) {
		s := DefaultSettings()
		s.Test.Tags = []string{"tag1", "tag2"}
		s.Build.FIPSBuild = false

		tags := s.TestTagsWithFIPS()

		assert.Equal(t, []string{"tag1", "tag2"}, tags)
	})

	t.Run("appends FIPS tags when FIPS enabled", func(t *testing.T) {
		s := DefaultSettings()
		s.Test.Tags = []string{"tag1"}
		s.Build.FIPSBuild = true

		tags := s.TestTagsWithFIPS()

		assert.Equal(t, []string{"tag1", "requirefips", "ms_tls13kdf"}, tags)
	})

	t.Run("does not modify original tags", func(t *testing.T) {
		s := DefaultSettings()
		s.Test.Tags = []string{"tag1"}
		s.Build.FIPSBuild = true

		_ = s.TestTagsWithFIPS()

		assert.Equal(t, []string{"tag1"}, s.Test.Tags)
	})

	t.Run("handles nil tags with FIPS enabled", func(t *testing.T) {
		s := DefaultSettings()
		s.Test.Tags = nil
		s.Build.FIPSBuild = true

		tags := s.TestTagsWithFIPS()

		assert.Equal(t, []string{"requirefips", "ms_tls13kdf"}, tags)
	})
}

func TestSettingsGetPackageTypes(t *testing.T) {
	t.Run("returns SelectedPackageTypes when set", func(t *testing.T) {
		s := DefaultSettings()
		s.SelectedPackageTypes = []PackageType{TarGz, Zip}
		s.CrossBuild.Packages = "rpm,deb" // should be ignored

		types := s.GetPackageTypes()

		assert.Equal(t, []PackageType{TarGz, Zip}, types)
	})

	t.Run("parses from env var when SelectedPackageTypes is nil", func(t *testing.T) {
		s := DefaultSettings()
		s.CrossBuild.Packages = "targz,zip"

		types := s.GetPackageTypes()

		assert.Equal(t, []PackageType{TarGz, Zip}, types)
	})

	t.Run("returns nil when both are empty", func(t *testing.T) {
		s := DefaultSettings()

		types := s.GetPackageTypes()

		assert.Nil(t, types)
	})
}

func TestSettingsGetDockerVariants(t *testing.T) {
	t.Run("returns SelectedDockerVariants when set", func(t *testing.T) {
		s := DefaultSettings()
		s.SelectedDockerVariants = []DockerVariant{Basic, Cloud}
		s.CrossBuild.DockerVariants = "complete" // should be ignored

		variants := s.GetDockerVariants()

		assert.Equal(t, []DockerVariant{Basic, Cloud}, variants)
	})

	t.Run("parses from env var when SelectedDockerVariants is nil", func(t *testing.T) {
		s := DefaultSettings()
		s.CrossBuild.DockerVariants = "basic,cloud"

		variants := s.GetDockerVariants()

		assert.Equal(t, []DockerVariant{Basic, Cloud}, variants)
	})

	t.Run("returns nil when both are empty", func(t *testing.T) {
		s := DefaultSettings()

		variants := s.GetDockerVariants()

		assert.Nil(t, variants)
	})
}

func TestSettingsIsPackageTypeSelected(t *testing.T) {
	t.Run("returns true when no types selected", func(t *testing.T) {
		s := DefaultSettings()

		assert.True(t, s.IsPackageTypeSelected(TarGz))
		assert.True(t, s.IsPackageTypeSelected(Zip))
	})

	t.Run("returns true when type is in selected list", func(t *testing.T) {
		s := DefaultSettings()
		s.SelectedPackageTypes = []PackageType{TarGz, Zip}

		assert.True(t, s.IsPackageTypeSelected(TarGz))
		assert.True(t, s.IsPackageTypeSelected(Zip))
	})

	t.Run("returns false when type is not in selected list", func(t *testing.T) {
		s := DefaultSettings()
		s.SelectedPackageTypes = []PackageType{TarGz}

		assert.False(t, s.IsPackageTypeSelected(Zip))
		assert.False(t, s.IsPackageTypeSelected(RPM))
	})
}

func TestSettingsIsDockerVariantSelected(t *testing.T) {
	t.Run("returns true when no variants selected", func(t *testing.T) {
		s := DefaultSettings()

		assert.True(t, s.IsDockerVariantSelected(Basic))
		assert.True(t, s.IsDockerVariantSelected(Cloud))
	})

	t.Run("returns true when variant is in selected list", func(t *testing.T) {
		s := DefaultSettings()
		s.SelectedDockerVariants = []DockerVariant{Basic, Cloud}

		assert.True(t, s.IsDockerVariantSelected(Basic))
		assert.True(t, s.IsDockerVariantSelected(Cloud))
	})

	t.Run("returns false when variant is not in selected list", func(t *testing.T) {
		s := DefaultSettings()
		s.SelectedDockerVariants = []DockerVariant{Basic}

		assert.False(t, s.IsDockerVariantSelected(Cloud))
		assert.False(t, s.IsDockerVariantSelected(Complete))
	})
}

func TestSettingsContext(t *testing.T) {
	t.Run("ContextWithSettings stores settings", func(t *testing.T) {
		original := DefaultSettings()
		original.Build.DevBuild = true

		ctx := ContextWithSettings(context.Background(), original)
		retrieved := SettingsFromContext(ctx)

		assert.Same(t, original, retrieved)
		assert.True(t, retrieved.Build.DevBuild)
	})

	t.Run("SettingsFromContext returns fresh settings when not in context", func(t *testing.T) {
		ctx := context.Background()

		settings := SettingsFromContext(ctx)

		assert.NotNil(t, settings)
	})

	t.Run("SettingsFromContext returns fresh settings for nil value", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), settingsContextKey{}, (*Settings)(nil))

		settings := SettingsFromContext(ctx)

		assert.NotNil(t, settings)
	})
}

func TestSubstring(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		start    int
		length   int
		expected string
	}{
		{"normal substring", "hello world", 0, 5, "hello"},
		{"middle substring", "hello world", 6, 5, "world"},
		{"start at end", "hello", 5, 3, ""},
		{"negative start", "hello", -1, 3, ""},
		{"start beyond length", "hello", 10, 3, ""},
		{"length exceeds string", "hello", 0, 100, "hello"},
		{"length from middle exceeds", "hello", 3, 100, "lo"},
		{"empty string", "", 0, 5, ""},
		{"zero length", "hello", 0, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Substring(tt.s, tt.start, tt.length)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateSnapshotSuffix(t *testing.T) {
	t.Run("returns suffix when snapshot is true", func(t *testing.T) {
		result := GenerateSnapshotSuffix(true)
		assert.Equal(t, SnapshotSuffix, result)
	})

	t.Run("returns empty when snapshot is false", func(t *testing.T) {
		result := GenerateSnapshotSuffix(false)
		assert.Equal(t, "", result)
	})
}

func TestMaybeSnapshotSuffix(t *testing.T) {
	t.Run("returns suffix when snapshot is true", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.Snapshot = true

		result := MaybeSnapshotSuffix(s)

		assert.Equal(t, SnapshotSuffix, result)
	})

	t.Run("returns empty when snapshot is false", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.Snapshot = false

		result := MaybeSnapshotSuffix(s)

		assert.Equal(t, "", result)
	})
}

func TestBuildSettingsCommitHash(t *testing.T) {
	t.Run("returns override when set", func(t *testing.T) {
		bs := &BuildSettings{
			AgentCommitHashOverride: "abc123def456",
		}

		hash, err := bs.CommitHash()

		require.NoError(t, err)
		assert.Equal(t, "abc123def456", hash)
	})

	t.Run("caches git commit hash", func(t *testing.T) {
		bs := &BuildSettings{}

		hash1, err := bs.CommitHash()
		require.NoError(t, err)

		hash2, err := bs.CommitHash()
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2)
		assert.NotEmpty(t, hash1)
	})
}

func TestBuildSettingsCommitHashShort(t *testing.T) {
	t.Run("returns first 6 characters of hash", func(t *testing.T) {
		bs := &BuildSettings{
			AgentCommitHashOverride: "abc123def456789",
		}

		shortHash, err := bs.CommitHashShort()

		require.NoError(t, err)
		assert.Equal(t, "abc123", shortHash)
	})

	t.Run("returns full hash if less than 6 chars", func(t *testing.T) {
		bs := &BuildSettings{
			AgentCommitHashOverride: "abc",
		}

		shortHash, err := bs.CommitHashShort()

		require.NoError(t, err)
		assert.Equal(t, "abc", shortHash)
	})
}

func TestDefaultSettings(t *testing.T) {
	t.Run("sets all defaults correctly without reading env vars", func(t *testing.T) {
		// Set env vars that should NOT affect DefaultSettings()
		t.Setenv("BEAT_NAME", "should-be-ignored")
		t.Setenv("SNAPSHOT", "true")
		t.Setenv("DEV", "true")

		settings := DefaultSettings()

		assert.NotNil(t, settings)

		// Beat defaults - should not be affected by env vars
		assert.Equal(t, DefaultName, settings.Beat.Name)
		assert.Equal(t, DefaultName, settings.Beat.ServiceName)
		assert.Equal(t, DefaultName, settings.Beat.IndexPrefix)
		assert.Equal(t, DefaultDescription, settings.Beat.Description)
		assert.Equal(t, DefaultVendor, settings.Beat.Vendor)
		assert.Equal(t, DefaultLicense, settings.Beat.License)
		assert.Equal(t, DefaultUser, settings.Beat.User)
		assert.Equal(t, "https://www.elastic.co/beats/"+DefaultName, settings.Beat.URL)

		// Build defaults - should not be affected by env vars
		assert.False(t, settings.Build.Snapshot)
		assert.False(t, settings.Build.DevBuild)
		assert.Greater(t, settings.Build.MaxParallel, 0)

		// Dev machine defaults
		assert.Equal(t, DefaultDevMachineImage, settings.DevMachine.MachineImage)
		assert.Equal(t, DefaultDevMachineZone, settings.DevMachine.Zone)

		// CrossBuild defaults
		assert.Equal(t, "linux", settings.CrossBuild.DevOS)
		assert.Equal(t, "amd64", settings.CrossBuild.DevArch)
		assert.True(t, settings.CrossBuild.MountModcache)
		assert.True(t, settings.CrossBuild.MountBuildCache)
		assert.Equal(t, "elastic-agent-crossbuild-build-cache", settings.CrossBuild.BuildCacheVolumeName)

		// IntegrationTest defaults
		assert.True(t, settings.IntegrationTest.CleanOnExit)
		assert.True(t, settings.IntegrationTest.TestEnvironmentEnabled)
	})
}

func TestLoadSettings(t *testing.T) {
	t.Run("applies defaults before env vars", func(t *testing.T) {
		// No env vars set - should get defaults
		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.NotNil(t, settings)

		// Beat defaults
		assert.Equal(t, DefaultName, settings.Beat.Name)
		assert.Equal(t, DefaultName, settings.Beat.ServiceName)
		assert.Equal(t, DefaultName, settings.Beat.IndexPrefix)
		assert.Equal(t, DefaultDescription, settings.Beat.Description)
		assert.Equal(t, DefaultVendor, settings.Beat.Vendor)
		assert.Equal(t, DefaultLicense, settings.Beat.License)
		assert.Equal(t, DefaultUser, settings.Beat.User)

		// Dev machine defaults
		assert.Equal(t, DefaultDevMachineImage, settings.DevMachine.MachineImage)
		assert.Equal(t, DefaultDevMachineZone, settings.DevMachine.Zone)

		// CrossBuild defaults
		assert.Equal(t, "linux", settings.CrossBuild.DevOS)
		assert.Equal(t, "amd64", settings.CrossBuild.DevArch)
		assert.True(t, settings.CrossBuild.MountModcache)
		assert.True(t, settings.CrossBuild.MountBuildCache)

		// IntegrationTest defaults
		assert.True(t, settings.IntegrationTest.CleanOnExit)
		assert.True(t, settings.IntegrationTest.TestEnvironmentEnabled)
	})

	t.Run("loads build settings from env vars", func(t *testing.T) {
		t.Setenv("SNAPSHOT", "true")
		t.Setenv("DEV", "true")
		t.Setenv("EXTERNAL", "true")
		t.Setenv("FIPS", "true")
		t.Setenv("VERSION_QUALIFIER", "rc1")
		t.Setenv("CI", "true")
		t.Setenv("MAX_PARALLEL", "8")
		t.Setenv("BEAT_VERSION", "1.2.3")
		t.Setenv("AGENT_COMMIT_HASH_OVERRIDE", "abc123")
		t.Setenv("GOLANG_CROSSBUILD", "1")
		t.Setenv("BEAT_GO_VERSION", "1.21.0")
		t.Setenv("BEAT_DOC_BRANCH", "main")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.True(t, settings.Build.Snapshot)
		assert.True(t, settings.Build.SnapshotSet)
		assert.True(t, settings.Build.DevBuild)
		assert.True(t, settings.Build.ExternalBuild)
		assert.True(t, settings.Build.ExternalBuildSet)
		assert.True(t, settings.Build.FIPSBuild)
		assert.Equal(t, "rc1", settings.Build.VersionQualifier)
		assert.True(t, settings.Build.VersionQualified)
		assert.Equal(t, "true", settings.Build.CI)
		assert.Equal(t, 8, settings.Build.MaxParallel)
		assert.Equal(t, "1.2.3", settings.Build.BeatVersion)
		assert.Equal(t, "abc123", settings.Build.AgentCommitHashOverride)
		assert.True(t, settings.Build.GolangCrossBuild)
		assert.Equal(t, "1.21.0", settings.Build.BeatGoVersion)
		assert.Equal(t, "main", settings.Build.BeatDocBranch)
	})

	t.Run("loads beat settings from env vars", func(t *testing.T) {
		t.Setenv("BEAT_NAME", "custom-beat")
		t.Setenv("BEAT_SERVICE_NAME", "custom-service")
		t.Setenv("BEAT_INDEX_PREFIX", "custom-index")
		t.Setenv("BEAT_DESCRIPTION", "Custom description")
		t.Setenv("BEAT_VENDOR", "Custom Vendor")
		t.Setenv("BEAT_LICENSE", "MIT")
		t.Setenv("BEAT_URL", "https://custom.url")
		t.Setenv("BEAT_USER", "customuser")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.Equal(t, "custom-beat", settings.Beat.Name)
		assert.Equal(t, "custom-service", settings.Beat.ServiceName)
		assert.Equal(t, "custom-index", settings.Beat.IndexPrefix)
		assert.Equal(t, "Custom description", settings.Beat.Description)
		assert.Equal(t, "Custom Vendor", settings.Beat.Vendor)
		assert.Equal(t, "MIT", settings.Beat.License)
		assert.Equal(t, "https://custom.url", settings.Beat.URL)
		assert.Equal(t, "customuser", settings.Beat.User)
	})

	t.Run("loads test settings from env vars", func(t *testing.T) {
		t.Setenv("RACE_DETECTOR", "true")
		t.Setenv("TEST_COVERAGE", "true")
		t.Setenv("TEST_TAGS", "integration,e2e")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.True(t, settings.Test.RaceDetector)
		assert.True(t, settings.Test.Coverage)
		assert.Equal(t, []string{"integration", "e2e"}, settings.Test.Tags)
	})

	t.Run("loads cross-build settings from env vars", func(t *testing.T) {
		t.Setenv("PLATFORMS", "linux/amd64,darwin/arm64")
		t.Setenv("PACKAGES", "targz,zip")
		t.Setenv("DOCKER_VARIANTS", "basic,cloud")
		t.Setenv("CROSSBUILD_MOUNT_MODCACHE", "false")
		t.Setenv("CROSSBUILD_MOUNT_GOCACHE", "false")
		t.Setenv("DEV_OS", "darwin")
		t.Setenv("DEV_ARCH", "arm64")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.Equal(t, "linux/amd64,darwin/arm64", settings.CrossBuild.Platforms)
		assert.Equal(t, "targz,zip", settings.CrossBuild.Packages)
		assert.Equal(t, "basic,cloud", settings.CrossBuild.DockerVariants)
		assert.False(t, settings.CrossBuild.MountModcache)
		assert.False(t, settings.CrossBuild.MountBuildCache)
		assert.Equal(t, "darwin", settings.CrossBuild.DevOS)
		assert.Equal(t, "arm64", settings.CrossBuild.DevArch)
	})

	t.Run("loads packaging settings from env vars", func(t *testing.T) {
		t.Setenv("AGENT_PACKAGE_VERSION", "2.0.0")
		t.Setenv("MANIFEST_URL", "https://manifest.url")
		t.Setenv("USE_PACKAGE_VERSION", "true")
		t.Setenv("AGENT_DROP_PATH", "/drop/path")
		t.Setenv("KEEP_ARCHIVE", "true")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.Equal(t, "2.0.0", settings.Packaging.AgentPackageVersion)
		assert.Equal(t, "https://manifest.url", settings.Packaging.ManifestURL)
		assert.True(t, settings.Packaging.PackagingFromManifest)
		assert.True(t, settings.Packaging.UsePackageVersion)
		assert.Equal(t, "/drop/path", settings.Packaging.AgentDropPath)
		assert.True(t, settings.Packaging.KeepArchive)
	})

	t.Run("loads integration test settings from env vars", func(t *testing.T) {
		t.Setenv("AGENT_VERSION", "8.0.0")
		t.Setenv("AGENT_STACK_VERSION", "8.0.0")
		t.Setenv("AGENT_BUILD_DIR", "/build/dir")
		t.Setenv("STACK_PROVISIONER", "serverless")
		t.Setenv("INSTANCE_PROVISIONER", "kind")
		t.Setenv("TEST_PLATFORMS", "linux/amd64")
		t.Setenv("TEST_GROUPS", "default")
		t.Setenv("TEST_BINARY_NAME", "test-binary")
		t.Setenv("TEST_INTEG_TIMESTAMP", "true")
		t.Setenv("TEST_RUN_UNTIL_FAILURE", "true")
		t.Setenv("TEST_INTEG_CLEAN_ON_EXIT", "false")
		t.Setenv("BUILD_AGENT", "true")
		t.Setenv("GOTEST_FLAGS", "-v -count=1")
		t.Setenv("TEST_ENVIRONMENT", "false")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.Equal(t, "8.0.0", settings.IntegrationTest.AgentVersion)
		assert.Equal(t, "8.0.0", settings.IntegrationTest.AgentStackVersion)
		assert.Equal(t, "/build/dir", settings.IntegrationTest.AgentBuildDir)
		assert.Equal(t, "serverless", settings.IntegrationTest.StackProvisioner)
		assert.Equal(t, "kind", settings.IntegrationTest.InstanceProvisioner)
		assert.Equal(t, "linux/amd64", settings.IntegrationTest.Platforms)
		assert.Equal(t, "default", settings.IntegrationTest.Groups)
		assert.Equal(t, "test-binary", settings.IntegrationTest.BinaryName)
		assert.True(t, settings.IntegrationTest.TimestampEnabled)
		assert.True(t, settings.IntegrationTest.RunUntilFailure)
		assert.False(t, settings.IntegrationTest.CleanOnExit)
		assert.True(t, settings.IntegrationTest.BuildAgent)
		assert.Equal(t, "-v -count=1", settings.IntegrationTest.GoTestFlags)
		assert.False(t, settings.IntegrationTest.TestEnvironmentEnabled)
	})

	t.Run("loads docker settings from env vars", func(t *testing.T) {
		t.Setenv("DOCKER_IMPORT_SOURCE", "docker.elastic.co")
		t.Setenv("CUSTOM_IMAGE_TAG", "custom-tag")
		t.Setenv("CI_ELASTIC_AGENT_DOCKER_IMAGE", "ci-image")
		t.Setenv("DOCKER_NOCACHE", "1")
		t.Setenv("DOCKER_PULL", "1")
		t.Setenv("WINDOWS_NPCAP", "true")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.Equal(t, "docker.elastic.co", settings.Docker.ImportSource)
		assert.Equal(t, "custom-tag", settings.Docker.CustomImageTag)
		assert.Equal(t, "ci-image", settings.Docker.CIElasticAgentDockerImage)
		assert.True(t, settings.Docker.NoCache)
		assert.True(t, settings.Docker.ForcePull)
		assert.True(t, settings.Docker.WindowsNpcap)
	})

	t.Run("loads kubernetes settings from env vars", func(t *testing.T) {
		t.Setenv("K8S_VERSION", "1.28")
		t.Setenv("KIND_SKIP_DELETE", "true")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.Equal(t, "1.28", settings.Kubernetes.K8sVersion)
		assert.True(t, settings.Kubernetes.KindSkipDelete)
	})

	t.Run("loads dev machine settings from env vars", func(t *testing.T) {
		t.Setenv("MACHINE_IMAGE", "custom-image")
		t.Setenv("ZONE", "us-west1-b")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.Equal(t, "custom-image", settings.DevMachine.MachineImage)
		assert.Equal(t, "us-west1-b", settings.DevMachine.Zone)
	})

	t.Run("loads fmt settings from env vars", func(t *testing.T) {
		t.Setenv("CHECK_HEADERS_DISABLED", "1")

		settings, err := LoadSettings()

		require.NoError(t, err)
		assert.True(t, settings.Fmt.CheckHeadersDisabled)
	})

	t.Run("returns error for invalid bool env vars", func(t *testing.T) {
		t.Setenv("SNAPSHOT", "invalid")

		_, err := LoadSettings()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SNAPSHOT")
	})
}

func TestMustLoadSettings(t *testing.T) {
	t.Run("returns settings without panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			settings := MustLoadSettings()
			assert.NotNil(t, settings)
		})
	})
}

func TestEnvMap(t *testing.T) {
	t.Run("includes settings values", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)
		cfg.Build.GOOS = "linux"
		cfg.Build.GOARCH = "amd64"
		cfg.Beat.Name = "test-beat"

		envMap := EnvMap(cfg)

		assert.Equal(t, "linux", envMap["GOOS"])
		assert.Equal(t, "amd64", envMap["GOARCH"])
		assert.Equal(t, "test-beat", envMap["BeatName"])
	})

	t.Run("merges additional args", func(t *testing.T) {
		cfg, err := LoadSettings()
		require.NoError(t, err)

		envMap := EnvMap(cfg, map[string]interface{}{
			"CustomKey": "CustomValue",
		})

		assert.Equal(t, "CustomValue", envMap["CustomKey"])
	})
}
