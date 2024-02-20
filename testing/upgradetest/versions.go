// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgradetest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
)

var (
	// Version_8_2_0 is the first version to include --non-interactive flag during install
	Version_8_2_0 = version.NewParsedSemVer(8, 2, 0, "", "")
	// Version_8_6_0 is the first version to use agent v2 protocol
	Version_8_6_0 = version.NewParsedSemVer(8, 6, 0, "", "")
	// Version_8_7_0 is the minimum version for passing --skip-verify when upgrading
	Version_8_7_0 = version.NewParsedSemVer(8, 7, 0, "", "")
	// Version_8_9_0_SNAPSHOT is the minimum version for upgrade to specific snapshot + minimum version
	// for setting shorter watch period after upgrade
	Version_8_9_0_SNAPSHOT = version.NewParsedSemVer(8, 9, 0, "SNAPSHOT", "")
	// Version_8_10_0_SNAPSHOT is the minimum version for upgrade with remote pgp and skipping
	// default pgp verification
	Version_8_10_0_SNAPSHOT = version.NewParsedSemVer(8, 10, 0, "SNAPSHOT", "")
	// Version_8_11_0_SNAPSHOT is the minimum version for uninstall command to kill the watcher upon uninstall
	Version_8_11_0_SNAPSHOT = version.NewParsedSemVer(8, 11, 0, "SNAPSHOT", "")
	// Version_8_13_0 is the minimum version for proper unprivileged execution
	Version_8_13_0 = version.NewParsedSemVer(8, 13, 0, "", "")
)

// GetUpgradableVersions returns the version that the upgradeToVersion can upgrade from.
func GetUpgradableVersions(ctx context.Context, upgradeToVersion string, currentMajorVersions int, previousMajorVersions int) ([]*version.ParsedSemVer, error) {
	aac := tools.NewArtifactAPIClient()
	vList, err := aac.GetVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving versions from Artifact API: %w", err)
	}
	if len(vList.Versions) == 0 {
		return nil, errors.New("retrieved versions list from Artifact API is empty")
	}
	err = aac.RemoveUnreleasedVersions(ctx, vList)
	if err != nil {
		return nil, fmt.Errorf("failed to remove unreleased versions: %w", err)
	}

	return getUpgradableVersions(ctx, vList, upgradeToVersion, currentMajorVersions, previousMajorVersions)
}

// Internal version of GetUpgradableVersions() with the artifacts API dependency removed for testing.
func getUpgradableVersions(ctx context.Context, vList *tools.VersionList, upgradeToVersion string, currentMajorVersions int, previousMajorVersions int) ([]*version.ParsedSemVer, error) {
	parsedUpgradeToVersion, err := version.ParseVersion(upgradeToVersion)
	if err != nil {
		return nil, fmt.Errorf("upgradeToVersion %q is not a valid version string: %w", upgradeToVersion, err)
	}

	currentMajor := parsedUpgradeToVersion.Major()
	var currentMajorSelected, previousMajorSelected int

	sortedParsedVersions := make(version.SortableParsedVersions, 0, len(vList.Versions))
	for _, v := range vList.Versions {
		pv, err := version.ParseVersion(v)
		if err != nil {
			return nil, fmt.Errorf("invalid version %q retrieved from artifact API: %w", v, err)
		}
		sortedParsedVersions = append(sortedParsedVersions, pv)
	}

	if len(sortedParsedVersions) == 0 {
		return nil, errors.New("parsed versions list is empty")
	}

	// normally the output of the versions returned by artifact API is already sorted in ascending order,
	// we want to sort in descending orders, so we sort them
	sort.Sort(sort.Reverse(sortedParsedVersions))

	// If the only available build of the most recent version is a snapshot it is unreleased.
	// This is always true on main and true until the first release of each minor version branch.
	mostRecentVersion := sortedParsedVersions[0]
	mostRecentIsUnreleased := mostRecentVersion.IsSnapshot()

	var upgradableVersions []*version.ParsedSemVer
	for _, parsedVersion := range sortedParsedVersions {
		if currentMajorSelected == currentMajorVersions && previousMajorSelected == previousMajorVersions {
			// we got all the versions we need, break the loop
			break
		}

		if !parsedVersion.Less(*parsedUpgradeToVersion) {
			// skip as testing version is less than version to upgrade from
			continue
		}

		isPrevMinor := (parsedUpgradeToVersion.Major() == parsedVersion.Major()) &&
			(parsedUpgradeToVersion.Minor()-parsedVersion.Minor()) == 1

		if parsedVersion.IsSnapshot() {
			// Allow returning the snapshot build of the previous minor if the current version is unreleased.
			// In this situation the previous minor branch may also be unreleased immediately after feature freeze.
			if !mostRecentIsUnreleased || !isPrevMinor {
				continue
			}
		} else {
			// Skip the non-snapshot build of the previous minor since it might only be available at
			// staging.elastic.co which is not a default binary download location.
			if mostRecentIsUnreleased && isPrevMinor {
				continue
			}
		}

		if parsedVersion.Major() == currentMajor && currentMajorSelected < currentMajorVersions {
			upgradableVersions = append(upgradableVersions, parsedVersion)
			currentMajorSelected++
			continue
		}

		if parsedVersion.Major() < currentMajor && previousMajorSelected < previousMajorVersions {
			upgradableVersions = append(upgradableVersions, parsedVersion)
			previousMajorSelected++
			continue
		}

	}
	return upgradableVersions, nil
}

// PreviousMinor gets the previous minor version of the provided version.
//
// This checks with the artifact API to ensure to only return version that have actual builds.
func PreviousMinor(ctx context.Context, version string) (string, error) {
	versions, err := GetUpgradableVersions(ctx, version, 1, 0)
	if err != nil {
		return "", err
	}
	if len(version) == 0 {
		return "", fmt.Errorf("no previous minor")
	}
	return versions[0].String(), nil
}

// EnsureSnapshot ensures that the version string is a snapshot version.
func EnsureSnapshot(version string) string {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		version += "-SNAPSHOT"
	}
	return version
}
