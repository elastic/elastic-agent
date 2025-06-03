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
	assert.Truef(t, currentParsed.Major() == v.Major() && currentParsed.Minor() > v.Minor(), "%s is not previous minor for %s", v, bversion.Agent)
	assert.Empty(t, v.Prerelease())
	assert.Empty(t, v.BuildMetadata())
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
