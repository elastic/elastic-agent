// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgradetest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

// Response from https://artifacts-api.elastic.co/v1/versions shortly after the 8.12 feature freeze.
var versionListAfter8_11FeatureFreeze = tools.VersionList{
	Versions: []string{
		"7.17.11",
		"7.17.12",
		"7.17.13",
		"7.17.14",
		"7.17.15-SNAPSHOT",
		"7.17.15",
		"7.17.16-SNAPSHOT",
		"7.17.16",
		"8.8.2",
		"8.9.0",
		"8.9.1",
		"8.9.2",
		"8.10.0",
		"8.10.1",
		"8.10.2",
		"8.10.3",
		"8.10.4",
		"8.11.0",
		"8.11.1-SNAPSHOT",
		"8.11.1",
		"8.11.2-SNAPSHOT",
		"8.11.2",
		"8.11.3-SNAPSHOT",
		"8.11.3",
		"8.12.0-SNAPSHOT",
		"8.12.0",
	},
	Aliases: []string{
		"7.17-SNAPSHOT",
		"7.17",
		"8.8",
		"8.9",
		"8.10",
		"8.11-SNAPSHOT",
		"8.11",
		"8.12-SNAPSHOT",
		"8.12",
	},
	Manifests: tools.Manifests{
		LastUpdateTime:         "Mon, 11 Dec 2023 21:35:37 UTC",
		SecondsSinceLastUpdate: 236,
	},
}

// Tests that GetUpgradableVersions behaves correctly during the feature freeze period
// where the both main and the previous minor release branch versions are unreleased.
// Regression test for the problem described in https://github.com/elastic/elastic-agent/pull/3563#issuecomment-1756007790.
func TestGetUpgradableVersionsAfterFeatureFreeze(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start from 8.12.0 assuming the 8.12.0 feature freeze has just happened but the
	// first 8.13.0-SNAPSHOT hasn't been produced yet.
	//
	// The 8.11.3 release is upgradable because the first 8.11.3 build candidate exists,
	// but it is only available from staging.elastic.co which is not a binary download
	// source that is supported by default.
	currentVersion := "8.12.0-SNAPSHOT"

	// Since the 8.11.3 BC at staging.elastic.co isn't available to the agent by default,
	// getUpgradableVersions should return 8.11.3-SNAPSHOT as the previous minor so an
	// upgrade can proceed.
	expectedUpgradableVersions := []string{
		"8.11.3-SNAPSHOT", "8.11.2", "8.11.1", "7.17.16-SNAPSHOT", "7.17.15",
	}

	// Get several of the previous versions to ensure snapshot selection works correctly.
	versions, err := getUpgradableVersions(ctx, &versionListAfter8_11FeatureFreeze, currentVersion, 3, 2)
	require.NoError(t, err)
	require.NotEmpty(t, versions)

	t.Logf("exp: %s", expectedUpgradableVersions)
	t.Logf("act: %s", versions)
	for i, exp := range expectedUpgradableVersions {
		require.Equal(t, exp, versions[i].String())
	}
}
