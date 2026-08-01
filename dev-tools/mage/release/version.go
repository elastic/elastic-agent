// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"strconv"
	"strings"
)

type semver struct {
	major, minor, patch int
}

func parseSemver(version string) (semver, error) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semver{}, fmt.Errorf("invalid major version: %s", parts[0])
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return semver{}, fmt.Errorf("invalid minor version: %s", parts[1])
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return semver{}, fmt.Errorf("invalid patch version: %s", parts[2])
	}
	return semver{major: major, minor: minor, patch: patch}, nil
}

func (v semver) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func (v semver) less(other semver) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

// selectLatestReleaseBefore picks the highest same-major version strictly less than current.
func selectLatestReleaseBefore(versions []string, currentVersion string) (string, error) {
	current, err := parseSemver(currentVersion)
	if err != nil {
		return "", err
	}

	var best *semver
	for _, raw := range versions {
		candidate, err := parseSemver(raw)
		if err != nil {
			continue
		}
		if candidate.major != current.major {
			continue
		}
		if !candidate.less(current) {
			continue
		}
		if best == nil || best.less(candidate) {
			c := candidate
			best = &c
		}
	}
	if best == nil {
		return "", fmt.Errorf("no published release found before %s (same major)", currentVersion)
	}
	return best.String(), nil
}
