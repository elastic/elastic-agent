// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"github.com/elastic/elastic-agent/pkg/version"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// test 2 current 8.x version and 1 previous 7.x version
	versionList, err := upgradetest.GetUpgradableVersions(ctx, define.Version(), 2, 1)
	require.NoError(t, err)

	for _, startVersion := range versionList {
		t.Run(fmt.Sprintf("Upgrade %s to %s", startVersion, define.Version()), func(t *testing.T) {
			startFixture, err := atesting.NewFixture(
				t,
				startVersion.String(),
				atesting.WithFetcher(atesting.ArtifactFetcher()),
			)
			require.NoError(t, err, "error creating previous agent fixture")

			endFixture, err := define.NewFixture(t, define.Version())
			require.NoError(t, err)

			err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t)
			assert.NoError(t, err)
		})
	}
}

func TestStandaloneUpgradeUnprivileged(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: UpgradeUnprivileged,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)
	if currentVersion.Less(*upgradetest.Version_8_12_0_SNAPSHOT) {
		t.Skipf("Version %s is lower than min version %s; test cannot be performed", define.Version(), upgradetest.Version_8_12_0_SNAPSHOT)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// this can only currently test upgrading from snapshot 8.12 to build of 8.12.
	startFixture, err := atesting.NewFixture(
		t,
		upgradetest.EnsureSnapshot(define.Version()),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err, "error creating previous agent fixture")

	endFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradetest.WithUnprivileged(true))
	assert.NoError(t, err)
}
