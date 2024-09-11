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

var (
	versionList = []string{
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
	}
	snapshotList = []string{
		"7.17.19-SNAPSHOT",
		"8.12.2-SNAPSHOT",
		"8.13.0-SNAPSHOT",
		"8.14.0-SNAPSHOT",
	}
)

func TestFetchUpgradableVersionsAfterFeatureFreeze(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedUpgradableVersions := []string{
		"8.13.0-SNAPSHOT",
		"8.12.2",
		"8.12.2-SNAPSHOT",
		"8.12.1",
		"8.12.0",
		"8.11.4",
		"7.17.18",
	}

	reqs := VersionRequirements{
		UpgradeToVersion: "8.13.0",                 // to test that 8.14 is not returned
		CurrentMajors:    3,                        // should return 8.12.2, 8.12.1, 8.12.0
		PreviousMajors:   3,                        // should return 7.17.18
		PreviousMinors:   2,                        // should return 8.12.2, 8.11.4
		SnapshotBranches: []string{"8.13", "8.12"}, // should return 8.13.0-SNAPSHOT, 8.12.2-SNAPSHOT
	}

	vf := fetcherMock{
		list: buildVersionList(t, versionList),
	}
	sf := fetcherMock{
		list: buildVersionList(t, snapshotList),
	}

	versions, err := FetchUpgradableVersions(ctx, vf, sf, reqs)
	require.NoError(t, err)
	assert.Equal(t, expectedUpgradableVersions, versions)
}

func TestGetUpgradableVersions(t *testing.T) {
	versions, err := GetUpgradableVersions()
	require.NoError(t, err)
	assert.Truef(t, len(versions) > 1, "expected at least one version for testing, got %d.\n%v", len(versions), versions)
}

func TestPreviousMinor(t *testing.T) {
	currentParsed, err := version.ParseVersion(bversion.Agent)
	require.NoError(t, err)

	if currentParsed.Minor() == 0 {
		t.Skipf("skipping TestPreviousMinor as current major version (%v) don't have previous minor", bversion.Agent)
	}

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
