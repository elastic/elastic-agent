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
	// Version_8_11_0_SNAPSHOT is the minimum version for uninstall command to kill the watcher upon uninstall
	Version_8_11_0_SNAPSHOT = version.NewParsedSemVer(8, 11, 0, "SNAPSHOT", "")
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

	return getUpgradableVersions(ctx, vList, upgradeToVersion, currentMajorVersions, previousMajorVersions)
}

// The same as version.SortableParsedVersions but considers prerelease (SNAPSHOT) versions as newer.
type sortableWithGreaterPrerelease []*version.ParsedSemVer

func (spv sortableWithGreaterPrerelease) Len() int      { return len(spv) }
func (spv sortableWithGreaterPrerelease) Swap(i, j int) { spv[i], spv[j] = spv[j], spv[i] }
func (spv sortableWithGreaterPrerelease) Less(i, j int) bool {
	return spv[i].LessWithGreaterPrerelease(*spv[j])
}

// Internal version of GetUpgradableVersions() with the artifacts API dependency removed for testing.
func getUpgradableVersions(ctx context.Context, vList *tools.VersionList, upgradeToVersion string, currentMajorVersions int, previousMajorVersions int) ([]*version.ParsedSemVer, error) {
	parsedUpgradeToVersion, err := version.ParseVersion(upgradeToVersion)
	if err != nil {
		return nil, fmt.Errorf("upgradeToVersion %q is not a valid version string: %w", upgradeToVersion, err)
	}

	currentMajor := parsedUpgradeToVersion.Major()
	var currentMajorSelected, previousMajorSelected int

	sortedParsedVersions := make(sortableWithGreaterPrerelease, 0, len(vList.Versions))
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
	fmt.Println(sortedParsedVersions)

	// Set of upgradable snapsot minor releases (considering only the major.minor release numbers).
	// The latest minor release for each minor branch is considered upgradable to ensure we always test
	// against the latest changes.
	upgradeableSnapshotMinors := map[string]bool{}
	var upgradableVersions []*version.ParsedSemVer
	for _, parsedVersion := range sortedParsedVersions {
		if currentMajorSelected == currentMajorVersions && previousMajorSelected == previousMajorVersions {
			// we got all the versions we need, break the loop
			break
		}

		if !parsedVersion.Less(*parsedUpgradeToVersion) {
			// skip as testing version is less than or the same version to upgrade from
			continue
		}

		// Check if the last version in the upgradable list is the same as the current version.
		// This is the case if the snapshot version of the current version is in the upgradable list.
		if len(upgradableVersions) > 0 {
			prevVersion := upgradableVersions[len(upgradableVersions)-1]
			if prevVersion.CoreVersion() == parsedVersion.CoreVersion() {
				continue
			}
		}

		// If there is already a snapshot release in this major.minor release branch, skip all other
		// snapshots in this minor release series.
		if parsedVersion.Prerelease() != "" {
			minor := fmt.Sprintf("%d.%d", parsedVersion.Major(), parsedVersion.Minor())
			exists := upgradeableSnapshotMinors[minor]
			if exists {
				continue
			}
			upgradeableSnapshotMinors[minor] = true
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
