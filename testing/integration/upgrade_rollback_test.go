// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// TestStandaloneUpgradeRollback tests the scenario where upgrading to a new version
// of Agent fails due to the new Agent binary reporting an unhealthy status. It checks
// that the Agent is rolled back to the previous version.
func TestStandaloneUpgradeRollback(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err, "failed to get start agent build version info")

	// Upgrade to an old build, see `BackwardTwoMinors` for why.
	upgradeToVersion, err := upgradetest.BackwardTwoMinors(define.Version())
	require.NoError(t, err)
	endFixture, err := atesting.NewFixture(
		t,
		upgradeToVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), upgradeToVersion)

	// Configure Agent with fast watcher configuration and also an invalid
	// input when the Agent version matches the upgraded Agent version. This way
	// the pre-upgrade version of the Agent runs healthy, but the post-upgrade
	// version doesn't.
	preInstallHook := func() error {
		invalidInputPolicy := upgradetest.FastWatcherCfg + fmt.Sprintf(`
outputs:
  default:
    type: elasticsearch
    hosts: [127.0.0.1:9200]

inputs:
  - condition: '${agent.version.version} == "%s"'
    type: invalid
    id: invalid-input
`, upgradeToVersion)
		return startFixture.Configure(ctx, []byte(invalidInputPolicy))
	}

	// Use the post-upgrade hook to bypass the remainder of the PerformUpgrade
	// because we want to do our own checks for the rollback.
	var ErrPostExit = errors.New("post exit")
	postUpgradeHook := func() error {
		return ErrPostExit
	}

	err = upgradetest.PerformUpgrade(
		ctx, startFixture, endFixture, t,
		upgradetest.WithPreInstallHook(preInstallHook),
		upgradetest.WithPostUpgradeHook(postUpgradeHook))
	if !errors.Is(err, ErrPostExit) {
		require.NoError(t, err)
	}

	// rollback should now occur

	// wait for the agent to be healthy and back at the start version
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 10*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	// rollback should stop the watcher
	// killTimeout is greater than timeout as the watcher should have been
	// stopped on its own, and we don't want this test to hide that fact
	err = upgradetest.WaitForNoWatcher(ctx, 2*time.Minute, 10*time.Second, 3*time.Minute)
	require.NoError(t, err)

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = upgradetest.CheckHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary)
	assert.NoError(t, err)
}
