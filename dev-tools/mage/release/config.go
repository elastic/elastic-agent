// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

// ReleaseConfig is the release automation configuration loaded via mage Settings.
type ReleaseConfig = devtools.ReleaseSettings

// fetchLatestReleaseBefore looks up the previous published release from GitHub.
// Tests may replace this to avoid network calls.
var fetchLatestReleaseBefore = func(token, owner, repo, current string) (string, error) {
	return NewGitHubClient(token).LatestReleaseBefore(owner, repo, current)
}

// EnsureLatestRelease sets LatestRelease when unset by querying elastic/elastic-agent releases.
func EnsureLatestRelease(c *ReleaseConfig) error {
	if err := c.EnsureParsedVersions(); err != nil {
		return err
	}
	if c.LatestReleaseVersion != nil {
		return nil
	}
	if c.LatestRelease != "" {
		return c.SetLatestReleaseFromString(c.LatestRelease)
	}

	latest, err := fetchLatestReleaseBefore(c.GitHubToken, releasesLookupOwner, releasesLookupRepo, c.NextRelease)
	if err != nil {
		return fmt.Errorf("failed to resolve LatestRelease from GitHub: %w", err)
	}
	if err := c.SetLatestReleaseFromString(latest); err != nil {
		return fmt.Errorf("failed to parse LatestRelease from GitHub (%s): %w", latest, err)
	}
	fmt.Printf("Resolved LatestRelease from %s/%s: %s\n", releasesLookupOwner, releasesLookupRepo, c.LatestRelease)
	return nil
}

// ValidateReleaseConfig checks if the configuration is valid for release workflows.
func ValidateReleaseConfig(c *ReleaseConfig) error {
	if err := c.EnsureParsedVersions(); err != nil {
		return err
	}

	if !c.DryRun && c.GitHubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN is required when not in dry-run mode")
	}

	return nil
}
