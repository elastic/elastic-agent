// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/version"
	bversion "github.com/elastic/elastic-agent/version"
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
	currentParsed, err := version.ParseVersion(bversion.Agent)
	require.NoError(t, err)

	v, err := PreviousMinor()
	require.NoError(t, err)
	t.Logf("previous minor: %s", v.String())

	// Special case: the current Agent version is the first release of a new
	// major (vX.0.x). In this case we expect the previous minor to be the
	// latest minor of the previous major.
	if currentParsed.Minor() == 0 {
		require.Equal(t, currentParsed.Major()-1, v.Major())

		// The list of versions returned by GetUpgradableVersions will not contain any
		// versions with the same major as the current version as the current version is
		// the first release of the major. Further, since this list is sorted in
		// descending order (newer versions first), we should expect the first item in the
		// list to be the latest minor of the previous major.
		versions, err := GetUpgradableVersions()
		require.NoError(t, err)
		require.Equal(t, versions[0], v)
		return
	}

	assert.Truef(t, currentParsed.Major() == v.Major() && currentParsed.Minor() > v.Minor(), "%s is not previous minor for %s", v, bversion.Agent)
	assert.Empty(t, v.Prerelease())
	assert.Empty(t, v.BuildMetadata())
}

// TestPreviousMinorIndependentRelease verifies how PreviousMinor treats independent artifact
// release (IAR) versions, i.e. those with build metadata matching ^build\d{12}.
func TestPreviousMinorIndependentRelease(t *testing.T) {
	testCases := []struct {
		name           string
		currentVersion string
		testVersions   []string
		expected       string
		expectedErr    error
	}{
		{
			name:           "IAR version is accepted as previous minor",
			currentVersion: "8.19.5",
			testVersions:   []string{"8.18.3+build202506011200", "8.17.4"},
			expected:       "8.18.3+build202506011200",
		},
		{
			name:           "IAR version is preferred over older GA when listed first",
			currentVersion: "9.2.0",
			testVersions:   []string{"9.1.5+build202506011200", "9.1.4", "9.0.8"},
			expected:       "9.1.5+build202506011200",
		},
		{
			name:           "GA version listed before IAR version is preferred",
			currentVersion: "9.2.0",
			testVersions:   []string{"9.1.5", "9.1.4+build202506011200"},
			expected:       "9.1.5",
		},
		{
			name:           "non-IAR build metadata is skipped",
			currentVersion: "8.19.5",
			testVersions:   []string{"8.18.3+someothermetadata", "8.17.4"},
			expected:       "8.17.4",
		},
		{
			name:           "build metadata with fewer than 12 digits is skipped",
			currentVersion: "8.19.5",
			testVersions:   []string{"8.18.3+build2025060112", "8.17.4"},
			expected:       "8.17.4",
		},
		{
			name:           "prerelease IAR version is skipped",
			currentVersion: "8.19.5",
			testVersions:   []string{"8.18.3-SNAPSHOT+build202506011200", "8.17.4"},
			expected:       "8.17.4",
		},
		{
			name:           "IAR version of the current minor is not a previous minor",
			currentVersion: "8.19.5",
			testVersions:   []string{"8.19.4+build202506011200", "8.18.3"},
			expected:       "8.18.3",
		},
		{
			name:           "only non-matching versions yields ErrNoPreviousMinor",
			currentVersion: "8.19.5",
			testVersions:   []string{"8.18.3+someothermetadata", "8.19.4+build202506011200"},
			expectedErr:    ErrNoPreviousMinor,
		},
		{
			name:           "first release of a new major returns the newest IAR version of the previous major",
			currentVersion: "9.0.0",
			testVersions:   []string{"8.19.5+build202506011200", "8.19.4"},
			expected:       "8.19.5+build202506011200",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalVersions := agentVersions
			t.Cleanup(func() { agentVersions = originalVersions })
			agentVersions = &AgentVersions{TestVersions: tc.testVersions}
			t.Setenv("AGENT_VERSION", tc.currentVersion)

			v, err := PreviousMinor()
			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, v.String())
		})
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
