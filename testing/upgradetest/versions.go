// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgradetest

import (
	"context"
	"errors"
	"fmt"
	"sort"

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
)

// GetUpgradableVersions returns the version that the upgradeToVersion can upgrade from.
func GetUpgradableVersions(ctx context.Context, upgradeToVersion string) ([]*version.ParsedSemVer, error) {
	const currentMajorVersions = 2
	const previousMajorVersions = 1

	aac := tools.NewArtifactAPIClient()
	vList, err := aac.GetVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving versions from Artifact API: %w", err)
	}
	if len(vList.Versions) == 0 {
		return nil, errors.New("retrieved versions list from Artifact API is empty")
	}

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

		if parsedVersion.IsSnapshot() {
			// skip all snapshots
			continue
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
