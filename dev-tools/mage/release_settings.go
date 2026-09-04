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
// Loaded as part of Settings via LoadSettings(). CURRENT_RELEASE is optional during
// general mage loads; release targets call RequireRelease() before running workflows.
type ReleaseSettings struct {
	CurrentRelease          string
	LatestRelease           string
	NextRelease             string
	NextProjectMinorVersion string
	NextProjectMinorBranch  string

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

// RequireRelease ensures CURRENT_RELEASE was provided so inferred release fields are set.
func (s *Settings) RequireRelease() error {
	if s.Release.CurrentRelease == "" {
		return fmt.Errorf("CURRENT_RELEASE environment variable is required")
	}
	return nil
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
// When CURRENT_RELEASE is unset, non-version fields may still be overridden; inferred
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

	currentRelease := os.Getenv("CURRENT_RELEASE")
	if currentRelease == "" {
		return nil
	}

	return s.populateReleaseFromCurrent(currentRelease)
}

func (s *Settings) populateReleaseFromCurrent(currentRelease string) error {
	parsed, err := ParseReleaseVersion(currentRelease)
	if err != nil {
		return err
	}

	s.Release.CurrentRelease = parsed.CoreVersion()
	s.Release.LatestRelease = InferLatestRelease(parsed)
	s.Release.NextRelease = InferNextRelease(parsed)
	s.Release.ReleaseBranch = InferReleaseBranch(parsed)
	s.Release.NextProjectMinorVersion = InferNextProjectMinorVersion(parsed)
	s.Release.NextProjectMinorBranch = InferNextProjectMinorBranch(parsed)
	return nil
}

// ParseReleaseVersion parses a release version string as major.minor.patch with no
// prerelease or build metadata (e.g. CURRENT_RELEASE=9.5.0).
func ParseReleaseVersion(currentRelease string) (*version.ParsedSemVer, error) {
	parsed, err := version.ParseVersion(strings.TrimSpace(currentRelease))
	if err != nil {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch): %w", currentRelease, err)
	}
	if parsed.Prerelease() != "" || parsed.BuildMetadata() != "" {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch without prerelease/build metadata)", currentRelease)
	}
	return parsed, nil
}

// InferLatestRelease calculates the previous release version (patch - 1).
// For minor releases (patch == 0), returns empty string; callers may resolve via GitHub.
func InferLatestRelease(v *version.ParsedSemVer) string {
	if v.Patch() == 0 {
		return ""
	}
	return version.NewParsedSemVer(v.Major(), v.Minor(), v.Patch()-1, "", "").CoreVersion()
}

// InferNextRelease returns the next patch version (patch + 1).
func InferNextRelease(v *version.ParsedSemVer) string {
	return version.NewParsedSemVer(v.Major(), v.Minor(), v.Patch()+1, "", "").CoreVersion()
}

// InferReleaseBranch returns the major.minor release branch name.
func InferReleaseBranch(v *version.ParsedSemVer) string {
	return fmt.Sprintf("%d.%d", v.Major(), v.Minor())
}

// InferNextProjectMinorVersion returns the next minor version as major.(minor+1).0.
func InferNextProjectMinorVersion(v *version.ParsedSemVer) string {
	return version.NewParsedSemVer(v.Major(), v.Minor()+1, 0, "", "").CoreVersion()
}

// InferNextProjectMinorBranch returns the next minor branch as major.(minor+1).
func InferNextProjectMinorBranch(v *version.ParsedSemVer) string {
	return fmt.Sprintf("%d.%d", v.Major(), v.Minor()+1)
}
