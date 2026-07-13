// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReleaseConfig holds the configuration for release operations.
type ReleaseConfig struct {
	CurrentRelease string
	LatestRelease  string
	NextRelease    string

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

// LoadConfigFromEnv loads release configuration from environment variables.
func LoadConfigFromEnv() (*ReleaseConfig, error) {
	currentRelease := os.Getenv("CURRENT_RELEASE")
	if currentRelease == "" {
		return nil, fmt.Errorf("CURRENT_RELEASE environment variable is required")
	}

	latestRelease, err := inferLatestRelease(currentRelease)
	if err != nil {
		return nil, fmt.Errorf("failed to infer LatestRelease: %w", err)
	}

	nextRelease, err := inferNextRelease(currentRelease)
	if err != nil {
		return nil, fmt.Errorf("failed to infer NextRelease: %w", err)
	}

	releaseBranch := inferReleaseBranch(currentRelease)

	if envLatest := os.Getenv("LATEST_RELEASE"); envLatest != "" {
		latestRelease = envLatest
	}
	if envNext := os.Getenv("NEXT_RELEASE"); envNext != "" {
		nextRelease = envNext
	}
	if envBranch := os.Getenv("RELEASE_BRANCH"); envBranch != "" {
		releaseBranch = envBranch
	}

	cfg := &ReleaseConfig{
		CurrentRelease: currentRelease,
		LatestRelease:  latestRelease,
		NextRelease:    nextRelease,
		BaseBranch:     getEnvOrDefault("BASE_BRANCH", "main"),
		ReleaseBranch:  releaseBranch,
		ProjectOwner:   getEnvOrDefault("PROJECT_OWNER", "elastic"),
		ProjectRepo:    getEnvOrDefault("PROJECT_REPO", "elastic-agent"),
		GitHubToken:    os.Getenv("GITHUB_TOKEN"),
		GitAuthorName:  getEnvOrDefault("GIT_AUTHOR_NAME", "elastic-machine"),
		GitAuthorEmail: getEnvOrDefault("GIT_AUTHOR_EMAIL", "infra-root+elasticmachine@elastic.co"),
		DryRun:         getEnvOrDefault("DRY_RUN", "false") == "true",
	}

	reviewers := getEnvOrDefault("PROJECT_REVIEWERS", "elastic/elastic-agent-release")
	cfg.ProjectReviewers = strings.Split(reviewers, ",")

	return cfg, nil
}

// LoadReleaseConfigFromEnv is a deprecated alias for LoadConfigFromEnv.
func LoadReleaseConfigFromEnv() (*ReleaseConfig, error) {
	return LoadConfigFromEnv()
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func inferLatestRelease(currentRelease string) (string, error) {
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

func inferNextRelease(currentRelease string) (string, error) {
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

func inferReleaseBranch(currentRelease string) string {
	parts := strings.Split(currentRelease, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return ""
}

// Validate checks if the configuration is valid.
func (c *ReleaseConfig) Validate() error {
	if c.CurrentRelease == "" {
		return fmt.Errorf("CurrentRelease is required")
	}

	if !c.DryRun && c.GitHubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN is required when not in dry-run mode")
	}

	return nil
}
