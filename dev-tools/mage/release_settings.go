// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"os"
	"strings"

	"github.com/elastic/elastic-agent/pkg/version"
)

// ReleaseSettings holds configuration for release automation (feature freeze / patch).
// Loaded as part of Settings via LoadSettings(). NEXT_RELEASE is optional during
// general mage loads; release targets call RequireRelease() before running workflows.
//
// Versions are parsed once into *version.ParsedSemVer fields. String fields are
// derived at that time for call sites that need serialized values (PR titles,
// file writes). Workflow logic should use the parsed fields, not re-parse strings.
type ReleaseSettings struct {
	LatestReleaseVersion *version.ParsedSemVer
	NextProjectMinor     *version.ParsedSemVer
	NextReleaseVersion   *version.ParsedSemVer

	LatestRelease           string
	NextProjectMinorBranch  string
	NextProjectMinorVersion string
	NextRelease             string

	BaseBranch    string
	ReleaseBranch string

	ProjectOwner     string
	ProjectRepo      string
	GitHubToken      string
	ProjectReviewers []string

	GitAuthorName  string
	GitAuthorEmail string

	DryRun bool
}

// RequireRelease ensures NEXT_RELEASE was provided so inferred release fields are set.
func (s *Settings) RequireRelease() error {
	if s.Release.NextRelease == "" && s.Release.NextReleaseVersion == nil {
		return fmt.Errorf("NEXT_RELEASE environment variable is required")
	}
	return s.Release.EnsureParsedVersions()
}

func (s *Settings) setReleaseDefaults() {
	s.Release.BaseBranch = "main"
	s.Release.ProjectOwner = "elastic"
	s.Release.ProjectRepo = "elastic-agent"
	s.Release.GitAuthorName = "elastic-machine"
	s.Release.GitAuthorEmail = "infra-root+elasticmachine@elastic.co"
	s.Release.ProjectReviewers = []string{"elastic/elastic-agent-release"}
	s.Release.DryRun = false
}

// loadReleaseSettingsFromEnv overrides release settings from environment variables.
// When NEXT_RELEASE is unset, non-version fields may still be overridden; inferred
// version fields remain empty so unrelated mage targets keep working.
func (s *Settings) loadReleaseSettingsFromEnv() error {
	if v := os.Getenv("BASE_BRANCH"); v != "" {
		s.Release.BaseBranch = v
	}
	if v := os.Getenv("PROJECT_OWNER"); v != "" {
		s.Release.ProjectOwner = v
	}
	if v := os.Getenv("PROJECT_REPO"); v != "" {
		s.Release.ProjectRepo = v
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		s.Release.GitHubToken = v
	}
	if v := os.Getenv("GIT_AUTHOR_NAME"); v != "" {
		s.Release.GitAuthorName = v
	}
	if v := os.Getenv("GIT_AUTHOR_EMAIL"); v != "" {
		s.Release.GitAuthorEmail = v
	}
	if v := os.Getenv("DRY_RUN"); v != "" {
		s.Release.DryRun = v == "true"
	}
	if v := os.Getenv("PROJECT_REVIEWERS"); v != "" {
		s.Release.ProjectReviewers = strings.Split(v, ",")
	}

	nextRelease := os.Getenv("NEXT_RELEASE")
	if nextRelease == "" {
		return nil
	}

	return s.Release.populateFromNext(nextRelease)
}

// EnsureParsedVersions fills parsed version fields from NextRelease when missing.
// Production loads set these in populateFromNext; tests may set only the string.
// An explicitly set LatestRelease string is preserved when inference leaves it empty
// (minor releases with patch 0).
func (s *ReleaseSettings) EnsureParsedVersions() error {
	if s.NextReleaseVersion != nil {
		if s.LatestReleaseVersion == nil && s.LatestRelease != "" {
			return s.SetLatestReleaseFromString(s.LatestRelease)
		}
		return nil
	}
	if s.NextRelease == "" {
		return fmt.Errorf("NextRelease is required")
	}
	latestOverride := s.LatestRelease
	if err := s.populateFromNext(s.NextRelease); err != nil {
		return err
	}
	if latestOverride != "" && s.LatestReleaseVersion == nil {
		return s.SetLatestReleaseFromString(latestOverride)
	}
	return nil
}

func (s *ReleaseSettings) populateFromNext(nextRelease string) error {
	parsed, err := ParseReleaseVersion(nextRelease)
	if err != nil {
		return err
	}

	s.NextReleaseVersion = parsed
	s.NextRelease = parsed.CoreVersion()

	s.LatestReleaseVersion = InferLatestRelease(parsed)
	s.LatestRelease = CoreVersionString(s.LatestReleaseVersion)

	s.ReleaseBranch = InferReleaseBranch(parsed)

	s.NextProjectMinor = InferNextProjectMinorVersion(parsed)
	s.NextProjectMinorVersion = CoreVersionString(s.NextProjectMinor)
	s.NextProjectMinorBranch = InferNextProjectMinorBranch(parsed)
	return nil
}

// ParseReleaseVersion parses a release version string as major.minor.patch with no
// prerelease or build metadata (e.g. NEXT_RELEASE=9.5.0).
func ParseReleaseVersion(nextRelease string) (*version.ParsedSemVer, error) {
	parsed, err := version.ParseVersion(strings.TrimSpace(nextRelease))
	if err != nil {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch): %w", nextRelease, err)
	}
	if parsed.Prerelease() != "" || parsed.BuildMetadata() != "" {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch without prerelease/build metadata)", nextRelease)
	}
	return parsed, nil
}

// CoreVersionString returns v.CoreVersion(), or "" when v is nil.
func CoreVersionString(v *version.ParsedSemVer) string {
	if v == nil {
		return ""
	}
	return v.CoreVersion()
}

// InferLatestRelease returns the previous patch version (patch - 1).
// For minor releases (patch == 0), returns nil; callers may resolve via GitHub.
func InferLatestRelease(v *version.ParsedSemVer) *version.ParsedSemVer {
	if v.Patch() == 0 {
		return nil
	}
	return version.NewParsedSemVer(v.Major(), v.Minor(), v.Patch()-1, "", "")
}

// InferReleaseBranch returns the major.minor release branch name.
func InferReleaseBranch(v *version.ParsedSemVer) string {
	return fmt.Sprintf("%d.%d", v.Major(), v.Minor())
}

// InferNextProjectMinorVersion returns the next minor version as major.(minor+1).0.
func InferNextProjectMinorVersion(v *version.ParsedSemVer) *version.ParsedSemVer {
	return version.NewParsedSemVer(v.Major(), v.Minor()+1, 0, "", "")
}

// InferNextProjectMinorBranch returns the next minor branch as major.(minor+1).
func InferNextProjectMinorBranch(v *version.ParsedSemVer) string {
	return fmt.Sprintf("%d.%d", v.Major(), v.Minor()+1)
}

// SetLatestReleaseFromString parses and stores a previously published release version.
func (s *ReleaseSettings) SetLatestReleaseFromString(raw string) error {
	parsed, err := ParseReleaseVersion(raw)
	if err != nil {
		return err
	}
	s.LatestReleaseVersion = parsed
	s.LatestRelease = parsed.CoreVersion()
	return nil
}
