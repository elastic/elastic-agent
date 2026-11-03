// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent/pkg/version"
)

// selectLatestReleaseBefore picks the highest same-major version strictly less than current.
func selectLatestReleaseBefore(versions []string, currentVersion string) (string, error) {
	current, err := parseReleaseTag(currentVersion)
	if err != nil {
		return "", err
	}

	var best *version.ParsedSemVer
	for _, raw := range versions {
		candidate, err := parseReleaseTag(raw)
		if err != nil {
			continue
		}
		if candidate.Major() != current.Major() {
			continue
		}
		if !candidate.Less(*current) {
			continue
		}
		if best == nil || best.Less(*candidate) {
			best = candidate
		}
	}
	if best == nil {
		return "", fmt.Errorf("no published release found before %s (same major)", currentVersion)
	}
	return best.CoreVersion(), nil
}

// parseReleaseTag parses a GitHub release tag or version string as core major.minor.patch.
// Leading "v" is stripped; prerelease and build metadata are rejected.
func parseReleaseTag(raw string) (*version.ParsedSemVer, error) {
	tag := strings.TrimSpace(raw)
	tag = strings.TrimPrefix(tag, "v")
	parsed, err := version.ParseVersion(tag)
	if err != nil {
		return nil, err
	}
	if parsed.Prerelease() != "" || parsed.BuildMetadata() != "" {
		return nil, fmt.Errorf("expected major.minor.patch without prerelease/build metadata: %s", raw)
	}
	return parsed, nil
}
