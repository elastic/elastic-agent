// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/version"
)

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
	combineSlices := func(slices ...[]string) []string {
		var result []string
		for _, s := range slices {
			result = append(result, s...)
		}
		return result
	}
	previousMinorVersions := []string{
		"8.19.15",
		"8.19.15+metadata",
		"8.19.15-SNAPSHOT",
		"8.19.15-SNAPSHOT+metadata",
		"8.19.1",
		"8.19.1+metadata",
		"8.19.1-SNAPSHOT",
		"8.19.1-SNAPSHOT+metadata",
		"8.19.0",
		"8.19.0+metadata",
		"8.19.0-SNAPSHOT",
		"8.19.0-SNAPSHOT+metadata",
		"8.18.15",
		"8.18.15+metadata",
		"8.18.15-SNAPSHOT",
		"8.18.15-SNAPSHOT+metadata",
		"8.18.1",
		"8.18.1+metadata",
		"8.18.1-SNAPSHOT",
		"8.18.1-SNAPSHOT+metadata",
		"8.18.0",
		"8.18.0+metadata",
		"8.18.0-SNAPSHOT",
		"8.18.0-SNAPSHOT+metadata",
		"8.17.15",
		"8.17.15+metadata",
		"8.17.15-SNAPSHOT",
		"8.17.15-SNAPSHOT+metadata",
		"8.17.1",
		"8.17.1+metadata",
		"8.17.1-SNAPSHOT",
		"8.17.1-SNAPSHOT+metadata",
		"8.17.0",
		"8.17.0+metadata",
		"8.17.0-SNAPSHOT",
		"8.17.0-SNAPSHOT+metadata",
	}

	versions9_0_0 := []string{
		"9.0.0",
		"9.0.0+metadata",
		"9.0.0-SNAPSHOT",
		"9.0.0-SNAPSHOT+metadata",
	}
	versions9_0_1 := []string{
		"9.0.1",
		"9.0.1+metadata",
		"9.0.1-SNAPSHOT",
		"9.0.1-SNAPSHOT+metadata",
	}
	versions9_0_15 := []string{
		"9.0.15",
		"9.0.15+metadata",
		"9.0.15-SNAPSHOT",
		"9.0.15-SNAPSHOT+metadata",
	}
	versions9_1_0 := []string{
		"9.1.0",
		"9.1.0+metadata",
		"9.1.0-SNAPSHOT",
		"9.1.0-SNAPSHOT+metadata",
	}
	versions9_1_1 := []string{
		"9.1.1",
		"9.1.1+metadata",
		"9.1.1-SNAPSHOT",
		"9.1.1-SNAPSHOT+metadata",
	}
	versions9_1_15 := []string{
		"9.1.15",
		"9.1.15+metadata",
		"9.1.15-SNAPSHOT",
		"9.1.15-SNAPSHOT+metadata",
	}
	versions9_2_0 := []string{
		"9.2.0",
		"9.2.0+metadata",
		"9.2.0-SNAPSHOT",
		"9.2.0-SNAPSHOT+metadata",
	}
	versions9_2_1 := []string{
		"9.2.1",
		"9.2.1+metadata",
		"9.2.1-SNAPSHOT",
		"9.2.1-SNAPSHOT+metadata",
	}
	versions9_2_15 := []string{
		"9.2.15",
		"9.2.15+metadata",
		"9.2.15-SNAPSHOT",
		"9.2.15-SNAPSHOT+metadata",
	}
	versions9_3_0 := []string{
		"9.3.0",
		"9.3.0+metadata",
		"9.3.0-SNAPSHOT",
		"9.3.0-SNAPSHOT+metadata",
	}

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
		currentVersion      string
		upgradeableVersions []string
		expected            map[string]releaseTypes
	}

	type testCases map[string]testCase

	tests := testCases{
		"First major version - only previous major versions": {
			currentVersion:      "9.0.0",
			upgradeableVersions: previousMinorVersions,
			expected:            allSameResult("8.19.15", ""),
		},
		"First major version - only newer major versions": {
			currentVersion:      "9.0.0",
			upgradeableVersions: combineSlices(versions9_2_0, versions9_1_0),
			expected:            noPreviousMinorResult,
		},
		"First major version - only current major version": {
			currentVersion:      "9.0.0",
			upgradeableVersions: versions9_0_0,
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
			currentVersion: "9.0.0",
			upgradeableVersions: combineSlices(
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				versions9_0_0,
				previousMinorVersions,
			),
			expected: map[string]releaseTypes{
				release: {
					expected: "9.0.0-SNAPSHOT",
					err:      "",
				},
				snapshot: {
					expected: "8.19.15",
					err:      "",
				},
				metadata: {
					expected: "9.0.0-SNAPSHOT",
					err:      "",
				},
				snapshotMetadata: {
					expected: "8.19.15",
					err:      "",
				},
			},
		},
		"First patch release of a new version - only previous major versions": {
			currentVersion:      "9.0.1",
			upgradeableVersions: previousMinorVersions,
			expected:            allSameResult("8.19.15", ""),
		},
		"First patch release of a new version - only newer major versions": {
			currentVersion: "9.0.1",
			upgradeableVersions: combineSlices(
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
			),
			expected: noPreviousMinorResult,
		},
		"First patch release of a new version - only current major versions": {
			currentVersion:      "9.0.1",
			upgradeableVersions: versions9_0_1,
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
			currentVersion: "9.0.1",
			upgradeableVersions: combineSlices(
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				versions9_0_0,
				previousMinorVersions,
			),
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
			currentVersion: "9.1.0",
			upgradeableVersions: combineSlices(
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				versions9_0_0,
				previousMinorVersions,
			),
			expected: allSameResult("9.0.15", ""),
		},
		"First minor release - only current major or higher versions": {
			currentVersion: "9.1.0",
			upgradeableVersions: combineSlices(
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
			),
			expected: noPreviousMinorResult,
		},
		"First minor release - only previous major versions": {
			currentVersion:      "9.1.0",
			upgradeableVersions: previousMinorVersions,
			expected:            noPreviousMinorResult,
		},
		"First patch of first minor - previous minor from the same major and previous major versions": {
			currentVersion: "9.1.1",
			upgradeableVersions: combineSlices(
				versions9_1_1,
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				versions9_0_0,
				previousMinorVersions,
			),
			expected: allSameResult("9.0.15", ""),
		},
		"First patch of first minor - only current major or higher versions": {
			currentVersion: "9.1.1",
			upgradeableVersions: combineSlices(
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
			),
			expected: noPreviousMinorResult,
		},
		"First patch of first minor - only previous major versions": {
			currentVersion:      "9.1.1",
			upgradeableVersions: previousMinorVersions,
			expected:            noPreviousMinorResult,
		},
		"Nth patch of first minor - previous minor from the same major and previous major versions": {
			currentVersion: "9.1.15",
			upgradeableVersions: combineSlices(
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				previousMinorVersions,
			),
			expected: allSameResult("9.0.15", ""),
		},
		"Nth patch of first minor - only current major or higher versions": {
			currentVersion: "9.1.15",
			upgradeableVersions: combineSlices(
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
			),
			expected: noPreviousMinorResult,
		},
		"Nth patch of first minor - only previous major versions": {
			currentVersion:      "9.1.15",
			upgradeableVersions: previousMinorVersions,
			expected:            noPreviousMinorResult,
		},
		"Nth major - previous minor from the same major and previous major versions": {
			currentVersion: "9.2.0",
			upgradeableVersions: combineSlices(
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				versions9_0_0,
				previousMinorVersions,
			),
			expected: allSameResult("9.1.15", ""),
		},
		"Nth major - only current major or higher versions": {
			currentVersion: "9.2.0",
			upgradeableVersions: combineSlices(
				versions9_3_0,
				versions9_2_15,
				versions9_2_1,
				versions9_2_0,
			),
			expected: noPreviousMinorResult,
		},
		"Nth major - only previous major versions": {
			currentVersion:      "9.2.0",
			upgradeableVersions: previousMinorVersions,
			expected:            noPreviousMinorResult,
		},
		"Nth major first patch - previous minor from the same major and previous major versions": {
			currentVersion: "9.2.1",
			upgradeableVersions: combineSlices(
				versions9_2_1,
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				versions9_0_0,
				previousMinorVersions,
			),
			expected: allSameResult("9.1.15", ""),
		},
		"Nth major first patch - only current major or higher versions": {
			currentVersion: "9.2.1",
			upgradeableVersions: combineSlices(
				versions9_3_0,
				versions9_2_15,
				versions9_2_1,
				versions9_2_0,
			),
			expected: noPreviousMinorResult,
		},
		"Nth major first patch - only previous major versions": {
			currentVersion:      "9.2.1",
			upgradeableVersions: previousMinorVersions,
			expected:            noPreviousMinorResult,
		},
		"Nth major Nth patch - previous minor from the same major and previous major versions": {
			currentVersion: "9.2.15",
			upgradeableVersions: combineSlices(
				versions9_2_15,
				versions9_2_1,
				versions9_2_0,
				versions9_1_15,
				versions9_1_1,
				versions9_1_0,
				versions9_0_15,
				versions9_0_1,
				versions9_0_0,
				previousMinorVersions,
			),
			expected: allSameResult("9.1.15", ""),
		},
		"Nth major Nth patch - only current major or higher versions": {
			currentVersion: "9.2.15",
			upgradeableVersions: combineSlices(
				versions9_3_0,
				versions9_2_15,
				versions9_2_1,
				versions9_2_0,
			),
			expected: noPreviousMinorResult,
		},
		"Nth major Nth patch - only previous major versions": {
			currentVersion:      "9.2.15",
			upgradeableVersions: previousMinorVersions,
			expected:            noPreviousMinorResult,
		},
		"Empty version range": {
			currentVersion:      "9.2.15",
			upgradeableVersions: []string{},
			expected:            noPreviousMinorResult,
		},
		"Unparsable current version": {
			currentVersion:      "invalid version",
			upgradeableVersions: previousMinorVersions,
			expected:            allSameResult("", "failed to parse the current version"),
		},
	}

	for name, testCase := range tests {
		versions := []*version.ParsedSemVer{}
		for _, v := range testCase.upgradeableVersions {
			parsed, err := version.ParseVersion(v)
			require.NoError(t, err)
			versions = append(versions, parsed)
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
