// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/kardianos/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

const reallyFastWatcherCfg = `
agent.upgrade.watcher:
  grace_period: 2m
  error_check.interval: 5s
`

const fastWatcherCfgWithRollbackWindow = `
agent.upgrade:
    watcher:
        grace_period: 2m
        error_check.interval: 5s
    rollback:
        window: 10m
`

// TestStandaloneUpgradeRollback tests the scenario where upgrading to a new version
// of Agent fails due to the new Agent binary reporting an unhealthy status. It checks
// that the Agent is rolled back to the previous version.
func TestStandaloneUpgradeRollback(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Upgrade from an old build because the new watcher from the new build will
	// be ran. Otherwise the test will run the old watcher from the old build.
	upgradeFromVersion, err := upgradetest.PreviousMinor()
	require.NoError(t, err)
	startFixture, err := atesting.NewFixture(
		t,
		upgradeFromVersion.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err, "failed to get start agent build version info")

	// Upgrade to the build under test.
	endFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", upgradeFromVersion, define.Version())

	// We need to use the core version in the condition below because -SNAPSHOT is
	// stripped from the ${agent.version.version} evaluation below.
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

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
`, endVersion.CoreVersion())
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
	if err != nil {
		// agent never got healthy, but we need to ensure the watcher is stopped before continuing (this
		// prevents this test failure from interfering with another test)
		// this kills the watcher instantly and waits for it to be gone before continuing
		watcherErr := upgradetest.WaitForNoWatcher(ctx, 1*time.Minute, time.Second, 100*time.Millisecond)
		if watcherErr != nil {
			t.Logf("failed to kill watcher due to agent not becoming healthy: %s", watcherErr)
		}
	}
	require.NoError(t, err)

	// ensure that upgrade details now show the state as UPG_ROLLBACK. This is only possible with Elastic
	// Agent versions >= 8.12.0.
	startVersion, err := version.ParseVersion(startVersionInfo.Binary.Version)
	require.NoError(t, err)

	if !startVersion.Less(*version.NewParsedSemVer(8, 12, 0, "", "")) {
		client := startFixture.Client()
		err = client.Connect(ctx)
		require.NoError(t, err)

		state, err := client.State(ctx)
		require.NoError(t, err)

		if state.State == cproto.State_UPGRADING {
			if state.UpgradeDetails == nil {
				t.Fatal("upgrade details in the state cannot be nil")
			}

			assert.Equal(t, details.StateRollback, details.State(state.UpgradeDetails.State))
			if !startVersion.Less(*upgradetest.Version_9_2_0_SNAPSHOT) {
				assert.Equal(t, details.ReasonWatchFailed, state.UpgradeDetails.Metadata.Reason)
			}
		} else {
			t.Logf("rollback finished, status is '%s', cannot check UpgradeDetails", state.State.String())
		}
	}

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

// TestStandaloneUpgradeRollbackOnRestarts tests the scenario where upgrading to a new version
// of Agent fails due to the new Agent binary not starting up. It checks that the Agent is
// rolled back to the previous version.
func TestStandaloneUpgradeRollbackOnRestarts(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	type fixturesSetupFunc func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture)
	testcases := []struct {
		name          string
		fixturesSetup fixturesSetupFunc
	}{
		{
			name: "upgrade from previous minor to current version",
			fixturesSetup: func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture) {
				// Upgrade from an old build because the new watcher from the new build will
				// be ran. Otherwise the test will run the old watcher from the old build.
				upgradeFromVersion, err := upgradetest.PreviousMinor()
				require.NoError(t, err)
				startFixture, err := atesting.NewFixture(
					t,
					upgradeFromVersion.String(),
					atesting.WithFetcher(atesting.ArtifactFetcher()),
				)
				require.NoError(t, err)

				// Upgrade to the build under test.
				endFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
				require.NoError(t, err)
				return startFixture, endFixture
			},
		},
		{
			name: "downgrade from current version to previous minor",
			fixturesSetup: func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture) {
				// Upgrade from the current build to an older one. The new watcher will be run anyway, and we can check
				// the postconditions on a rollback

				// Start from the build under test.
				fromFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
				require.NoError(t, err)

				// Downgrade to a previous version (doesn't really matter what)
				upgradeToVersion, err := upgradetest.PreviousMinor()
				require.NoError(t, err)
				toFixture, err := atesting.NewFixture(
					t,
					upgradeToVersion.String(),
					atesting.WithFetcher(atesting.ArtifactFetcher()),
				)
				require.NoError(t, err)

				return fromFixture, toFixture
			},
		},
		{
			name: "upgrade to a repackaged agent built from the same commit",
			fixturesSetup: func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture) {
				// Upgrade from the current build to the same build as Independent Agent Release.

				// Start from the build under test.
				fromFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
				require.NoError(t, err)

				// Create a new package with a different version (IAR-style)
				// modify the version with the "+buildYYYYMMDDHHMMSS"
				currentVersion, err := version.ParseVersion(define.Version())
				require.NoErrorf(t, err, "define.Version() %q is not parsable.", define.Version())

				newVersionBuildMetadata := "build" + time.Now().Format("20060102150405")
				parsedNewVersion := version.NewParsedSemVer(currentVersion.Major(), currentVersion.Minor(), currentVersion.Patch(), "", newVersionBuildMetadata)

				err = fromFixture.EnsurePrepared(t.Context())
				require.NoErrorf(t, err, "fixture should be prepared")

				// retrieve the compressed package file location
				srcPackage, err := fromFixture.SrcPackage(t.Context())
				require.NoErrorf(t, err, "error retrieving start fixture source package")

				versionForFixture, repackagedArchiveFile, err := repackageArchive(t, srcPackage, newVersionBuildMetadata, currentVersion, parsedNewVersion)
				require.NoError(t, err, "error repackaging the archive built from the same commit")

				// I wish I could just pass the location of the package on disk to the whole upgrade tests/fixture/fetcher code
				// but I would have to break too much code for that, when in Rome... add more code on top of inflexible code
				repackagedLocalFetcher := atesting.LocalFetcher(filepath.Dir(repackagedArchiveFile))
				toFixture, err := atesting.NewFixture(
					t,
					versionForFixture.String(),
					atesting.WithFetcher(repackagedLocalFetcher),
				)
				require.NoError(t, err)

				return fromFixture, toFixture
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
			defer cancel()
			from, to := tc.fixturesSetup(t)

			standaloneRollbackRestartTest(ctx, t, from, to)
		})
	}

}

// TestFleetManagedUpgradeRollbackOnRestarts tests the scenario where upgrading to a new version
// of Agent fails due to the new Agent binary not starting up. It checks that the Agent is
// rolled back to the previous version and that Fleet reports the correct informations
func TestFleetManagedUpgradeRollbackOnRestarts(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		Stack: &define.Stack{},
	})

	type fixturesSetupFunc func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture)
	testcases := []struct {
		name          string
		fixturesSetup fixturesSetupFunc
	}{
		{
			name: "downgrade from current version to previous minor",
			fixturesSetup: func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture) {
				// Upgrade from the current build to an older one. The new watcher will be run anyway, and we can check
				// the postconditions on a rollback

				// Start from the build under test.
				fromFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
				require.NoError(t, err)

				// Downgrade to a previous version (doesn't really matter what)
				upgradeToVersion, err := upgradetest.PreviousMinor()
				require.NoError(t, err)
				toFixture, err := atesting.NewFixture(
					t,
					upgradeToVersion.String(),
					atesting.WithFetcher(atesting.ArtifactFetcher()),
				)
				require.NoError(t, err)

				return fromFixture, toFixture
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
			defer cancel()
			from, to := tc.fixturesSetup(t)

			managedRollbackRestartTest(ctx, t, info, from, to)
		})
	}
}

// TestStandaloneUpgradeManualRollback tests the scenario where, after upgrading to a new version
// of Agent, a manual rollback is triggered. It checks that the Agent is rolled back to the previous version.
func TestStandaloneUpgradeManualRollback(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	type fixturesSetupFunc func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture)
	testcases := []struct {
		name          string
		fixturesSetup fixturesSetupFunc
	}{
		{
			name: "upgrade to a repackaged agent built from the same commit",
			fixturesSetup: func(t *testing.T) (from *atesting.Fixture, to *atesting.Fixture) {
				// Upgrade from the current build to the same build as Independent Agent Release.

				// Start from the build under test.
				fromFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
				require.NoError(t, err)

				// Create a new package with a different version (IAR-style)
				// modify the version with the "+buildYYYYMMDDHHMMSS"
				currentVersion, err := version.ParseVersion(define.Version())
				require.NoErrorf(t, err, "define.Version() %q is not parsable.", define.Version())

				newVersionBuildMetadata := "build" + time.Now().Format("20060102150405")
				parsedNewVersion := version.NewParsedSemVer(currentVersion.Major(), currentVersion.Minor(), currentVersion.Patch(), "", newVersionBuildMetadata)

				err = fromFixture.EnsurePrepared(t.Context())
				require.NoErrorf(t, err, "fixture should be prepared")

				// retrieve the compressed package file location
				srcPackage, err := fromFixture.SrcPackage(t.Context())
				require.NoErrorf(t, err, "error retrieving start fixture source package")

				versionForFixture, repackagedArchiveFile, err := repackageArchive(t, srcPackage, newVersionBuildMetadata, currentVersion, parsedNewVersion)
				require.NoError(t, err, "error repackaging the archive built from the same commit")

				repackagedLocalFetcher := atesting.LocalFetcher(filepath.Dir(repackagedArchiveFile))
				toFixture, err := atesting.NewFixture(
					t,
					versionForFixture.String(),
					atesting.WithFetcher(repackagedLocalFetcher),
				)
				require.NoError(t, err)

				return fromFixture, toFixture
			},
		},
	}

	// set up start ficture with a rollback window of 1h
	rollbackWindowConfig := `
agent.upgrade.rollback.window: 1h
`

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
			defer cancel()
			from, to := tc.fixturesSetup(t)

			err := from.Configure(ctx, []byte(rollbackWindowConfig))
			require.NoError(t, err, "error setting up rollback window")
			standaloneManualRollbackTest(ctx, t, from, to)
		})
	}

}

func managedRollbackRestartTest(ctx context.Context, t *testing.T, info *define.Info, from *atesting.Fixture, to *atesting.Fixture) {

	startVersionInfo, err := from.ExecVersion(ctx)
	require.NoError(t, err, "failed to get start agent build version info")

	endVersionInfo, err := to.ExecVersion(ctx)
	require.NoError(t, err, "failed to get end agent build version info")

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", from.Version(), endVersionInfo.Binary.String())

	policyUUID := uuid.Must(uuid.NewV4()).String()

	policy := kibana.AgentPolicy{
		Name:        fmt.Sprintf("%s-policy-%s", t.Name(), policyUUID),
		Namespace:   "default",
		Description: fmt.Sprintf("Rollback test policy %s (%s)", t.Name(), policyUUID),
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	// Use the post-upgrade hook to skip part of the PerformUpgrade (the checks during the grace period)
	// because we want to do our own checks for the rollback.
	var ErrSkipGrace = errors.New("skip grace period")
	postUpgradeHook := func() error {
		return ErrSkipGrace
	}

	err = PerformManagedUpgrade(ctx, t, info, from, to, policy, false,
		upgradetest.WithPostUpgradeHook(postUpgradeHook),
		upgradetest.WithDisableHashCheck(true),
		upgradetest.WithCustomWatcherConfig(reallyFastWatcherCfg),
	)

	// we expect ErrSkipGrace at this point, meaning that we finished installing but didn't wait for agent to become healthy
	require.ErrorIs(t, err, ErrSkipGrace, "managed upgrade failed with unexpected error")

	// A few seconds after the upgrade, deliberately restart upgraded Agent a
	// couple of times to simulate Agent crashing.
	restartAgentNTimes(t, 3, 10*time.Second)

	// wait for the agent to be healthy and correct version
	err = upgradetest.WaitHealthyAndVersion(ctx, from, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err, "agent never came online with version %s", startVersionInfo.Binary.String())

	agentID, err := from.AgentID(ctx)
	require.NoError(t, err, "error retrieving agent ID")

	// ensure that upgrade details now show the state as UPG_ROLLBACK. This is only possible with Elastic
	// Agent versions >= 8.12.0.
	startVersion, err := version.ParseVersion(startVersionInfo.Binary.Version)
	require.NoError(t, err)

	if !startVersion.Less(*version.NewParsedSemVer(8, 12, 0, "", "")) {
		fleetAgent, fleetAgentErr := info.KibanaClient.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
		require.NoError(t, fleetAgentErr, "error getting agent from Fleet")
		require.NotNil(t, fleetAgent.UpgradeDetails, "upgrade details not set")
		assert.Equal(t, details.StateRollback, details.State(fleetAgent.UpgradeDetails.State))
		if !startVersion.Less(*upgradetest.Version_9_2_0_SNAPSHOT) {
			assert.Equal(t, details.ReasonWatchFailed, fleetAgent.UpgradeDetails.Metadata.Reason)
		}
	}

	// rollback should stop the watcher
	// killTimeout is greater than timeout as the watcher should have been
	// stopped on its own, and we don't want this test to hide that fact
	err = upgradetest.WaitForNoWatcher(ctx, 2*time.Minute, 10*time.Second, 3*time.Minute)
	require.NoError(t, err)

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = upgradetest.CheckHealthyAndVersion(ctx, from, startVersionInfo.Binary)
	assert.NoError(t, err)

}

func standaloneRollbackRestartTest(ctx context.Context, t *testing.T, startFixture *atesting.Fixture, endFixture *atesting.Fixture) {
	standaloneRollbackTest(ctx, t, startFixture, endFixture, reallyFastWatcherCfg, details.ReasonWatchFailed,
		func(t *testing.T, _ client.Client) {
			restartAgentNTimes(t, 3, 10*time.Second)
		})
}

func standaloneManualRollbackTest(ctx context.Context, t *testing.T, startFixture *atesting.Fixture, endFixture *atesting.Fixture) {
	standaloneRollbackTest(ctx, t, startFixture, endFixture, fastWatcherCfgWithRollbackWindow, fmt.Sprintf(details.ReasonManualRollbackPattern, startFixture.Version()),
		func(t *testing.T, client client.Client) {
			t.Logf("sending version=%s rollback=%v upgrade to agent", startFixture.Version(), true)
			retVal, err := client.Upgrade(ctx, startFixture.Version(), true, "", false, false)
			require.NoError(t, err, "error triggering manual rollback to version %s", startFixture.Version())
			t.Logf("received output %s from upgrade command", retVal)
		},
	)
}

func standaloneRollbackTest(ctx context.Context, t *testing.T, startFixture *atesting.Fixture, endFixture *atesting.Fixture, customConfig string, rollbackReason string, rollbackTrigger func(t *testing.T, client client.Client)) {

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err, "failed to get start agent build version info")

	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err, "failed to get end agent build version info")

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", startFixture.Version(), endVersionInfo.Binary.String())

	// Use the post-upgrade hook to bypass the remainder of the PerformUpgrade
	// because we want to do our own checks for the rollback.
	var ErrPostExit = errors.New("post exit")
	postUpgradeHook := func() error {
		return ErrPostExit
	}

	err = upgradetest.PerformUpgrade(
		ctx, startFixture, endFixture, t,
		upgradetest.WithPostUpgradeHook(postUpgradeHook),
		upgradetest.WithCustomWatcherConfig(customConfig),
		upgradetest.WithDisableHashCheck(true),
	)
	if !errors.Is(err, ErrPostExit) {
		require.NoError(t, err)
	}

	elasticAgentClient := startFixture.Client()
	err = elasticAgentClient.Connect(ctx)
	require.NoError(t, err, "error connecting to installed elastic agent")
	defer elasticAgentClient.Disconnect()

	// A few seconds after the upgrade, trigger a rollback using the passed trigger
	rollbackTrigger(t, elasticAgentClient)

	// wait for the agent to be healthy and back at the start version
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	if err != nil {
		// agent never got healthy, but we need to ensure the watcher is stopped before continuing
		// this kills the watcher instantly and waits for it to be gone before continuing
		watcherErr := upgradetest.WaitForNoWatcher(ctx, 1*time.Minute, time.Second, 100*time.Millisecond)
		if watcherErr != nil {
			t.Logf("failed to kill watcher due to agent not becoming healthy: %s", watcherErr)
		}
	}
	require.NoError(t, err)

	// ensure that upgrade details now show the state as UPG_ROLLBACK. This is only possible with Elastic
	// Agent versions >= 8.12.0.
	startVersion, err := version.ParseVersion(startVersionInfo.Binary.Version)
	require.NoError(t, err)

	if !startVersion.Less(*version.NewParsedSemVer(8, 12, 0, "", "")) {
		require.NoError(t, err)

		state, err := elasticAgentClient.State(ctx)
		require.NoError(t, err)

		require.NotNil(t, state.UpgradeDetails)
		assert.Equal(t, details.StateRollback, details.State(state.UpgradeDetails.State))
		if !startVersion.Less(*upgradetest.Version_9_2_0_SNAPSHOT) {
			assert.Equal(t, rollbackReason, state.UpgradeDetails.Metadata.Reason)
		}
	}

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

func restartAgentNTimes(t *testing.T, noOfRestarts int, sleepBetweenIterations time.Duration) {
	topPath := paths.Top()

	for restartIdx := 0; restartIdx < noOfRestarts; restartIdx++ {
		time.Sleep(sleepBetweenIterations)

		t.Logf("Stopping agent via service to simulate crashing")
		err := install.StopService(topPath, install.DefaultStopTimeout, install.DefaultStopInterval)
		if err != nil && runtime.GOOS == define.Windows && strings.Contains(err.Error(), "The service has not been started.") {
			// Due to the quick restarts every 10 seconds its possible that this is faster than Windows
			// can handle. Decrementing restartIdx means that the loop will occur again.
			t.Logf("Got an allowed error on Windows: %s", err)
			err = nil
		}
		require.NoError(t, err)

		// ensure that it's stopped before starting it again
		var status service.Status
		var statusErr error
		require.Eventuallyf(t, func() bool {
			status, statusErr = install.StatusService(topPath)
			if statusErr != nil {
				return false
			}
			return status != service.StatusRunning
		}, 5*time.Minute, 1*time.Second, "service never fully stopped (status: %v): %s", status, statusErr)
		t.Logf("Stopped agent via service to simulate crashing")

		// start it again
		t.Logf("Starting agent via service to simulate crashing")
		err = install.StartService(topPath)
		require.NoError(t, err)

		// ensure that it's started before next loop
		require.Eventuallyf(t, func() bool {
			status, statusErr = install.StatusService(topPath)
			if statusErr != nil {
				return false
			}
			return status == service.StatusRunning
		}, 5*time.Minute, 1*time.Second, "service never fully started (status: %v): %s", status, statusErr)
		t.Logf("Started agent via service to simulate crashing")
	}
}
