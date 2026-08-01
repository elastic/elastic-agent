// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"os"
	"strconv"
	"strings"
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
	latestRelease, err := InferLatestRelease(currentRelease)
	if err != nil {
		return fmt.Errorf("failed to infer LatestRelease: %w", err)
	}

	nextRelease, err := InferNextRelease(currentRelease)
	if err != nil {
		return fmt.Errorf("failed to infer NextRelease: %w", err)
	}

	nextProjectMinorVersion, err := InferNextProjectMinorVersion(currentRelease)
	if err != nil {
		return fmt.Errorf("failed to infer NextProjectMinorVersion: %w", err)
	}

	s.Release.CurrentRelease = currentRelease
	s.Release.LatestRelease = latestRelease
	s.Release.NextRelease = nextRelease
	s.Release.ReleaseBranch = InferReleaseBranch(currentRelease)
	s.Release.NextProjectMinorVersion = nextProjectMinorVersion
	s.Release.NextProjectMinorBranch = InferNextProjectMinorBranch(currentRelease)
	return nil
}

// InferLatestRelease calculates the previous release version (patch - 1).
// For minor releases (patch == 0), returns empty string; callers may resolve via GitHub.
func InferLatestRelease(currentRelease string) (string, error) {
	parts := strings.Split(currentRelease, ".")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid version format: %s (expected major.minor.patch)", currentRelease)
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid patch version: %s", parts[2])
	}

	if patch == 0 {
		return "", nil
	}

	return fmt.Sprintf("%s.%s.%d", parts[0], parts[1], patch-1), nil
}

func InferNextRelease(currentRelease string) (string, error) {
	parts := strings.Split(currentRelease, ".")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid version format: %s (expected major.minor.patch)", currentRelease)
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid patch version: %s", parts[2])
	}

	return fmt.Sprintf("%s.%s.%d", parts[0], parts[1], patch+1), nil
}

func InferReleaseBranch(currentRelease string) string {
	parts := strings.Split(currentRelease, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return ""
}

func InferNextProjectMinorVersion(currentRelease string) (string, error) {
	parts := strings.Split(currentRelease, ".")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid version format: %s (expected major.minor.patch)", currentRelease)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid minor version: %s", parts[1])
	}

	return fmt.Sprintf("%s.%d.0", parts[0], minor+1), nil
}

func InferNextProjectMinorBranch(currentRelease string) string {
	parts := strings.Split(currentRelease, ".")
	if len(parts) < 2 {
		return ""
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%s.%d", parts[0], minor+1)
}
