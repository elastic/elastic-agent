// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/version"
)

func generateTestVersions(startVersion, endVersion string) ([]*version.ParsedSemVer, error) {
	var versionStrings []string
	start, err := version.ParseVersion(startVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid startVersion: %w", err)
	}
	end, err := version.ParseVersion(endVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid endVersion: %w", err)
	}

	if !start.Less(*end) && !start.Equal(*end) {
		return nil, fmt.Errorf("start version %s is newer than end version %s", startVersion, endVersion)
	}

	for major := start.Major(); major <= end.Major(); major++ {
		// Arbitrarily chosen well defined range of minor versions
		minorStart := 0
		minorEnd := 19

		if major == start.Major() {
			minorStart = start.Minor()
		}

		if major == end.Major() {
			minorEnd = end.Minor()
		}

		for minor := minorStart; minor <= minorEnd; minor++ {
			// Arbitrarily chosen well defined range of patch versions
			patchStart := 0
			patchEnd := 9
			if major == start.Major() && minor == start.Minor() {
				patchStart = start.Patch()
			}

			if major == end.Major() && minor == end.Minor() {
				patchEnd = end.Patch()
			}

			for patch := patchStart; patch <= patchEnd; patch++ {
				base := fmt.Sprintf("%d.%d.%d", major, minor, patch)
				versionStrings = append(versionStrings, base)
				versionStrings = append(versionStrings, base+"-SNAPSHOT")
				versionStrings = append(versionStrings, base+"+metadata")
				versionStrings = append(versionStrings, base+"-SNAPSHOT+metadata")
			}
		}
	}

	var versions []*version.ParsedSemVer
	for _, vStr := range versionStrings {
		parsed, err := version.ParseVersion(vStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse generated version %s: %w", vStr, err)
		}
		versions = append(versions, parsed)
	}

	// Sort from newest to oldest
	// Release and metadata versions are equal, sort lexicographicall
	sort.SliceStable(versions, func(i, j int) bool {
		if !versions[i].Equal(*versions[j]) {
			return versions[j].Less(*versions[i])
		}
		return versions[i].Original() < versions[j].Original()
	})

	return versions, nil
}

func TestGenerateTestVersions(t *testing.T) {
	testCases := map[string]struct {
		startVersion          string
		endVersion            string
		expectedNewestVersion string
		expectedOldestVersion string
		error                 string
	}{
		"8.17.2 to 9.2.0": {
			startVersion:          "8.17.2",
			endVersion:            "9.2.0",
			expectedNewestVersion: "9.2.0",
			expectedOldestVersion: "8.17.2-SNAPSHOT+metadata",
			error:                 "",
		},
		"9.0.0 to 9.20.0": {
			startVersion:          "9.0.0",
			endVersion:            "9.20.0",
			expectedNewestVersion: "9.20.0",
			expectedOldestVersion: "9.0.0-SNAPSHOT+metadata",
			error:                 "",
		},
		"9.0.0 to 9.0.0": {
			startVersion:          "9.0.0",
			endVersion:            "9.0.0",
			expectedNewestVersion: "9.0.0",
			expectedOldestVersion: "9.0.0-SNAPSHOT+metadata",
			error:                 "",
		},
		"invalid start version": {
			startVersion:          "invalid.version",
			endVersion:            "",
			expectedNewestVersion: "",
			expectedOldestVersion: "",
			error:                 "invalid startVersion:",
		},
		"invalid end version": {
			startVersion:          "9.0.0",
			endVersion:            "invalid.version",
			expectedNewestVersion: "",
			expectedOldestVersion: "",
			error:                 "invalid endVersion:",
		},
		"start version newer than end version": {
			startVersion:          "9.2.0",
			endVersion:            "9.0.0",
			expectedNewestVersion: "",
			expectedOldestVersion: "",
			error:                 "start version 9.2.0 is newer than end version 9.0.0",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			versions, err := generateTestVersions(tc.startVersion, tc.endVersion)

			if tc.error != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.error)
				require.Nil(t, versions)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, versions)

			for i := 1; i < len(versions); i++ {
				require.False(t, versions[i-1].Less(*versions[i]),
					"versions not sorted correctly: %s should not be less than %s",
					versions[i-1].Original(), versions[i].Original())
			}

			expectedNewestParsed, err := version.ParseVersion(tc.expectedNewestVersion)
			require.NoError(t, err)
			expectedOldestParsed, err := version.ParseVersion(tc.expectedOldestVersion)
			require.NoError(t, err)

			firstVersion := versions[0]
			require.True(t, firstVersion.Equal(*expectedNewestParsed),
				"first version %s should be equal to expected newest version %s",
				firstVersion.Original(), tc.expectedNewestVersion)

			lastVersion := versions[len(versions)-1]
			require.True(t, lastVersion.Equal(*expectedOldestParsed),
				"last version %s should be equal to expected oldest version %s",
				lastVersion.Original(), tc.expectedOldestVersion)
		})
	}
}

func TestFetchUpgradableVersionsAfterFeatureFreeze(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, tc := range []struct {
		name                       string
		expectedUpgradableVersions []string
		versionReqs                VersionRequirements
		fetchVersions              []string
		snapshotFetchVersions      []string
	}{
		{
			name: "generic case",
			expectedUpgradableVersions: []string{
				"8.12.2",
				"8.12.2-SNAPSHOT",
				"8.12.1",
				"8.12.0",
				"8.11.4",
				"7.17.19-SNAPSHOT",
				"7.17.18",
			},
			versionReqs: VersionRequirements{
				UpgradeToVersion: "8.13.0",                 // to test that 8.14 is not returned
				CurrentMajors:    3,                        // should return 8.12.2, 8.12.1, 8.12.0
				PreviousMajors:   3,                        // should return 7.17.18
				PreviousMinors:   2,                        // should return 8.12.2, 8.11.4
				SnapshotBranches: []string{"8.13", "8.12"}, // should return 8.13.0-SNAPSHOT, 8.12.2-SNAPSHOT
			},
			fetchVersions: []string{
				"7.17.13",
				"7.17.14",
				"7.17.15",
				"7.17.16",
				"7.17.17",
				"7.17.18",
				"8.9.2",
				"8.10.0",
				"8.10.1",
				"8.10.2",
				"8.10.3",
				"8.10.4",
				"8.11.0",
				"8.11.1",
				"8.11.2",
				"8.11.3",
				"8.11.4",
				"8.12.0",
				"8.12.1",
				"8.12.2",
				"8.13.0",
			},
			snapshotFetchVersions: []string{
				"7.17.19-SNAPSHOT",
				"8.12.2-SNAPSHOT",
				"8.13.0-SNAPSHOT",
				"8.14.0-SNAPSHOT",
			},
		},

		{
			name: "9.1.x case",
			expectedUpgradableVersions: []string{
				"9.0.2-SNAPSHOT",
				"9.0.1",
				"8.19.0-SNAPSHOT",
				"8.18.2",
				"7.17.29-SNAPSHOT",
			},
			versionReqs: VersionRequirements{
				UpgradeToVersion: "9.1.0",
				CurrentMajors:    1,
				PreviousMajors:   1,
				PreviousMinors:   2,
				SnapshotBranches: []string{"9.0", "8.19", "7.17"},
			},
			fetchVersions: []string{
				"7.17.27",
				"7.17.28",
				"8.17.5",
				"8.17.6",
				"8.18.1",
				"8.18.2",
				"9.0.1",
			},
			snapshotFetchVersions: []string{
				"7.17.29-SNAPSHOT",
				"8.19.0-SNAPSHOT",
				"9.0.2-SNAPSHOT",
			},
		},
		{
			name: "9.0.x case",
			expectedUpgradableVersions: []string{
				"8.19.0-SNAPSHOT",
				"8.18.2",
				"8.17.6",
				"7.17.29-SNAPSHOT",
			},
			versionReqs: VersionRequirements{
				UpgradeToVersion: "9.0.2",                         // to test that 8.14 is not returned
				CurrentMajors:    1,                               // should return 8.12.2, 8.12.1, 8.12.0
				PreviousMajors:   1,                               // should return 7.17.18
				PreviousMinors:   2,                               // should return 8.12.2, 8.11.4
				SnapshotBranches: []string{"9.0", "8.19", "7.17"}, // should return 8.13.0-SNAPSHOT, 8.12.2-SNAPSHOT
			},
			fetchVersions: []string{
				"7.17.28",
				"7.17.29",
				"8.17.5",
				"8.17.6",
				"8.18.1",
				"8.18.2",
				"9.0.1",
			},
			snapshotFetchVersions: []string{
				"7.17.29-SNAPSHOT",
				"8.19.0-SNAPSHOT",
				"9.0.3-SNAPSHOT",
			},
		},
		{
			name: "8.19.x case",
			expectedUpgradableVersions: []string{
				"8.18.2",
				"8.17.6",
				"7.17.29-SNAPSHOT",
				"7.17.28",
			},
			versionReqs: VersionRequirements{
				UpgradeToVersion: "8.19.0",
				CurrentMajors:    1,
				PreviousMajors:   1,
				PreviousMinors:   2,
				SnapshotBranches: []string{"9.0", "8.19", "7.17"},
			},
			fetchVersions: []string{
				"7.17.28",
				"8.17.5",
				"8.17.6",
				"8.18.1",
				"8.18.2",
				"9.0.1",
			},
			snapshotFetchVersions: []string{
				"7.17.29-SNAPSHOT",
				"8.19.0-SNAPSHOT", // this should be excluded
				"9.0.3-SNAPSHOT",
			},
		},
		{
			name: "8.18.x case",
			expectedUpgradableVersions: []string{
				"8.17.6",
				"8.16.6",
				"7.17.29-SNAPSHOT",
				"7.17.28",
			},
			versionReqs: VersionRequirements{
				UpgradeToVersion: "8.18.2",
				CurrentMajors:    1,
				PreviousMajors:   1,
				PreviousMinors:   2,
				SnapshotBranches: []string{"9.0", "8.19", "7.17"},
			},
			fetchVersions: []string{
				"7.17.28",
				"8.16.5",
				"8.16.6",
				"8.17.5",
				"8.17.6",
				"8.18.1",
				"8.18.2",
				"9.0.1",
			},
			snapshotFetchVersions: []string{
				"7.17.29-SNAPSHOT",
				"8.19.0-SNAPSHOT",
				"9.0.3-SNAPSHOT",
			},
		},
		{
			name: "8.17.x case",
			expectedUpgradableVersions: []string{
				"8.16.6",
				"7.17.29-SNAPSHOT",
				"7.17.28",
			},
			versionReqs: VersionRequirements{
				UpgradeToVersion: "8.17.6",
				CurrentMajors:    1,
				PreviousMajors:   1,
				PreviousMinors:   2,
				SnapshotBranches: []string{"9.0", "8.19", "7.17"},
			},
			fetchVersions: []string{
				"7.17.28",
				"8.16.5",
				"8.16.6",
				"8.17.5",
				"8.17.6",
				"8.18.1",
				"8.18.2",
				"9.0.1",
			},
			snapshotFetchVersions: []string{
				"7.17.29-SNAPSHOT",
				"8.19.0-SNAPSHOT",
				"9.0.3-SNAPSHOT",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vf := fetcherMock{
				list: buildVersionList(t, tc.fetchVersions),
			}
			sf := fetcherMock{
				list: buildVersionList(t, tc.snapshotFetchVersions),
			}

			upgradableVersions, err := FetchUpgradableVersions(ctx, vf, sf, tc.versionReqs)
			require.NoError(t, err)
			require.Equal(t, tc.expectedUpgradableVersions, upgradableVersions)
		})
	}
}

func TestGetUpgradableVersions(t *testing.T) {
	versions, err := GetUpgradableVersions()
	require.NoError(t, err)
	assert.Truef(t, len(versions) > 1, "expected at least one version for testing, got %d.\n%v", len(versions), versions)
}

func TestPreviousMinor(t *testing.T) {
	var (
		release          = ""
		snapshot         = "-SNAPSHOT"
		metadata         = "+metadata"
		snapshotMetadata = snapshot + metadata
	)

	type releaseTypes struct {
		expected string
		err      string
	}

	allSameResult := func(expected, err string) map[string]releaseTypes {
		return map[string]releaseTypes{
			release:          {expected: expected, err: err},
			snapshot:         {expected: expected, err: err},
			metadata:         {expected: expected, err: err},
			snapshotMetadata: {expected: expected, err: err},
		}
	}

	noPreviousMinorResult := allSameResult("", ErrNoPreviousMinor.Error())

	type testCase struct {
		currentVersion    string
		oldestCoreVersion string
		newestCoreVersion string
		expected          map[string]releaseTypes
	}

	type testCases map[string]testCase

	tests := testCases{
		"First major version - only previous major versions": {
			currentVersion:    "9.0.0",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          allSameResult("8.19.0", ""),
		},
		"First major version - only newer major versions": {
			currentVersion:    "9.0.0",
			oldestCoreVersion: "9.1.0",
			newestCoreVersion: "9.2.0",
			expected:          noPreviousMinorResult,
		},
		"First major version - only current major version": {
			currentVersion:    "9.0.0",
			oldestCoreVersion: "9.0.0",
			newestCoreVersion: "9.0.0",
			expected: map[string]releaseTypes{
				release: {
					expected: "9.0.0-SNAPSHOT",
					err:      "",
				},
				snapshot: {
					expected: "",
					err:      ErrNoPreviousMinor.Error(),
				},
				metadata: {
					expected: "9.0.0-SNAPSHOT",
					err:      "",
				},
				snapshotMetadata: {
					expected: "",
					err:      ErrNoPreviousMinor.Error(),
				},
			},
		},
		"First major version - current major, newer versions and older versions": {
			currentVersion:    "9.0.0",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.2.0",
			expected: map[string]releaseTypes{
				release: {
					expected: "9.0.0-SNAPSHOT",
					err:      "",
				},
				snapshot: {
					expected: "8.19.9",
					err:      "",
				},
				metadata: {
					expected: "9.0.0-SNAPSHOT",
					err:      "",
				},
				snapshotMetadata: {
					expected: "8.19.9",
					err:      "",
				},
			},
		},
		"First patch release of a new version - only previous major versions": {
			currentVersion:    "9.0.1",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          allSameResult("8.19.0", ""),
		},
		"First patch release of a new version - only newer major versions": {
			currentVersion:    "9.0.1",
			oldestCoreVersion: "9.1.0",
			newestCoreVersion: "9.2.0",
			expected:          noPreviousMinorResult,
		},
		"First patch release of a new version - only current major versions": {
			currentVersion:    "9.0.1",
			oldestCoreVersion: "9.0.1",
			newestCoreVersion: "9.0.1",
			expected: map[string]releaseTypes{
				release: {
					expected: "9.0.1-SNAPSHOT",
					err:      "",
				},
				snapshot: {
					expected: "",
					err:      ErrNoPreviousMinor.Error(),
				},
				metadata: {
					expected: "9.0.1-SNAPSHOT",
					err:      "",
				},
				snapshotMetadata: {
					expected: "",
					err:      ErrNoPreviousMinor.Error(),
				},
			},
		},
		"First patch release of a new version - current major, newer versions and older versions": {
			currentVersion:    "9.0.1",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.2.0",
			expected: map[string]releaseTypes{
				release: {
					expected: "9.0.1-SNAPSHOT",
					err:      "",
				},
				snapshot: {
					expected: "9.0.0",
					err:      "",
				},
				metadata: {
					expected: "9.0.1-SNAPSHOT",
					err:      "",
				},
				snapshotMetadata: {
					expected: "9.0.0",
					err:      "",
				},
			},
		},
		"First minor release - previous minor from the same major and previous major versions": {
			currentVersion:    "9.1.0",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.1.0",
			expected:          allSameResult("9.0.9", ""),
		},
		"First minor release - only current major or higher versions": {
			currentVersion:    "9.1.0",
			oldestCoreVersion: "9.1.0",
			newestCoreVersion: "9.2.0",
			expected:          noPreviousMinorResult,
		},
		"First minor release - only previous major versions": {
			currentVersion:    "9.1.0",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          noPreviousMinorResult,
		},
		"First patch of first minor - previous minor from the same major and previous major versions": {
			currentVersion:    "9.1.1",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.1.1",
			expected:          allSameResult("9.0.9", ""),
		},
		"First patch of first minor - only current major or higher versions": {
			currentVersion:    "9.1.1",
			oldestCoreVersion: "9.1.1",
			newestCoreVersion: "9.2.0",
			expected:          noPreviousMinorResult,
		},
		"First patch of first minor - only previous major versions": {
			currentVersion:    "9.1.1",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          noPreviousMinorResult,
		},
		"Nth patch of first minor - previous minor from the same major and previous major versions": {
			currentVersion:    "9.1.15",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.1.15",
			expected:          allSameResult("9.0.9", ""),
		},
		"Nth patch of first minor - only current major or higher versions": {
			currentVersion:    "9.1.15",
			oldestCoreVersion: "9.1.15",
			newestCoreVersion: "9.2.0",
			expected:          noPreviousMinorResult,
		},
		"Nth patch of first minor - only previous major versions": {
			currentVersion:    "9.1.15",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          noPreviousMinorResult,
		},
		"Nth major - previous minor from the same major and previous major versions": {
			currentVersion:    "9.2.0",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.2.0",
			expected:          allSameResult("9.1.9", ""),
		},
		"Nth major - only current major or higher versions": {
			currentVersion:    "9.2.0",
			oldestCoreVersion: "9.2.0",
			newestCoreVersion: "9.3.0",
			expected:          noPreviousMinorResult,
		},
		"Nth major - only previous major versions": {
			currentVersion:    "9.2.0",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          noPreviousMinorResult,
		},
		"Nth major first patch - previous minor from the same major and previous major versions": {
			currentVersion:    "9.2.1",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.2.1",
			expected:          allSameResult("9.1.9", ""),
		},
		"Nth major first patch - only current major or higher versions": {
			currentVersion:    "9.2.1",
			oldestCoreVersion: "9.2.0",
			newestCoreVersion: "9.3.0",
			expected:          noPreviousMinorResult,
		},
		"Nth major first patch - only previous major versions": {
			currentVersion:    "9.2.1",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          noPreviousMinorResult,
		},
		"Nth major Nth patch - previous minor from the same major and previous major versions": {
			currentVersion:    "9.2.15",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "9.2.15",
			expected:          allSameResult("9.1.9", ""),
		},
		"Nth major Nth patch - only current major or higher versions": {
			currentVersion:    "9.2.15",
			oldestCoreVersion: "9.2.15",
			newestCoreVersion: "9.3.0",
			expected:          noPreviousMinorResult,
		},
		"Nth major Nth patch - only previous major versions": {
			currentVersion:    "9.2.15",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          noPreviousMinorResult,
		},
		"Empty version range": {
			currentVersion:    "9.2.15",
			oldestCoreVersion: "",
			newestCoreVersion: "",
			expected:          noPreviousMinorResult,
		},
		"Unparsable current version": {
			currentVersion:    "invalid version",
			oldestCoreVersion: "8.17.0",
			newestCoreVersion: "8.19.0",
			expected:          allSameResult("", "failed to parse the current version"),
		},
	}

	for name, testCase := range tests {
		versions := version.SortableParsedVersions{}
		var err error
		if testCase.oldestCoreVersion != "" && testCase.newestCoreVersion != "" {
			versions, err = generateTestVersions(testCase.oldestCoreVersion, testCase.newestCoreVersion)
			require.NoError(t, err)
		}

		for versionType, vcase := range testCase.expected {
			testVersion := testCase.currentVersion
			if versionType != "" {
				testVersion = testCase.currentVersion + versionType
			}
			t.Run(name+" "+versionType, func(t *testing.T) {
				result, err := previousMinor(testVersion, versions)
				if vcase.err != "" {
					require.Error(t, err, func() string {
						if result != nil {
							return fmt.Sprintf("expected: %s, got: %s", vcase.expected, result.Original())
						}
						return fmt.Sprintf("expected: %s, got: <nil>", vcase.expected)
					}())

					require.Contains(t, err.Error(), vcase.err)
					return
				}

				require.NoError(t, err)
				expected, err := version.ParseVersion(vcase.expected)
				require.NoError(t, err)
				require.Equal(t, expected, result)
			})
		}
	}
}

func buildVersionList(t *testing.T, versions []string) version.SortableParsedVersions {
	result := make(version.SortableParsedVersions, 0, len(versions))
	for _, v := range versions {
		parsed, err := version.ParseVersion(v)
		require.NoError(t, err)
		result = append(result, parsed)
	}
	return result
}

type fetcherMock struct {
	list version.SortableParsedVersions
}

func (f fetcherMock) FetchAgentVersions(ctx context.Context) (version.SortableParsedVersions, error) {
	return f.list, nil
}

func (f fetcherMock) FindLatestSnapshots(ctx context.Context, branches []string) (version.SortableParsedVersions, error) {
	return f.list, nil
}
