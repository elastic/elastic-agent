// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.StandaloneUpgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	for _, startVersion := range versionList {
		unprivilegedAvailable := false
		if upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			unprivilegedAvailable = true
		}
		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			testStandaloneUpgrade(t, startVersion, define.Version(), atesting.ArtifactFetcher(), upgradetest.WithUnprivileged(false))
		})
		if unprivilegedAvailable {
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgrade(t, startVersion, define.Version(), atesting.ArtifactFetcher(), upgradetest.WithUnprivileged(true))
			})
		}
	}
}

func testStandaloneUpgrade(t *testing.T, startVersion *version.ParsedSemVer, endVersion string, fetcher atesting.Fetcher, upgradeOpts ...upgradetest.UpgradeOpt) {
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	startFixture, err := atesting.NewFixture(
		t,
		startVersion.String(),
		atesting.WithFetcher(fetcher),
	)
	require.NoError(t, err, "error creating previous agent fixture")

	endFixture, err := define.NewFixtureFromLocalBuild(t, endVersion)
	require.NoError(t, err)

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	if startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("both start and end versions have the same hash %q, skipping...", startVersionInfo.Binary.Commit)
		return
	}

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradeOpts...)
	assert.NoError(t, err)
}
