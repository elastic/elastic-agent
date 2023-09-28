// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/version"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgradeUninstallKillWatcher(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)
	if currentVersion.Less(*upgradetest.Version_8_11_0_SNAPSHOT) {
		t.Skipf("Version %s is lower than min version %s; test cannot be performed", define.Version(), upgradetest.Version_8_11_0_SNAPSHOT)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start at old version, we want this test to upgrade to our
	// build to ensure that the uninstall will kill the watcher.
	startVersion, err := upgradetest.PreviousMinor(ctx, define.Version())
	require.NoError(t, err)
	startFixture, err := atesting.NewFixture(
		t,
		startVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	// Upgrades to build under test.
	endFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err, "failed to get end agent build version info")

	// Use the post-upgrade hook to bypass the remainder of the PerformUpgrade
	// because we want to do our own checks for the rollback.
	var ErrPostExit = errors.New("post exit")
	postUpgradeHook := func() error {
		return ErrPostExit
	}

	err = upgradetest.PerformUpgrade(
		ctx, startFixture, endFixture, t,
		upgradetest.WithPostUpgradeHook(postUpgradeHook))
	if !errors.Is(err, ErrPostExit) {
		require.NoError(t, err)
	}

	// wait for the agent to be healthy and at the new version
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 10*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	// call uninstall now, do not wait for the watcher to finish running
	// 8.11+ should always kill the running watcher (if it doesn't uninstall will fail)
	uninstallCtx, uninstallCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer uninstallCancel()
	output, err := startFixture.Uninstall(uninstallCtx, &atesting.UninstallOpts{Force: true})
	assert.NoError(t, err, "uninstall failed with output:\n%s", string(output))
}
