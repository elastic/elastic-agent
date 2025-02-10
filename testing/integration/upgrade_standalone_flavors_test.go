// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

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
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgrade_Flavor_Basic(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_9_0_0_SNAPSHOT
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if currentVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	checkFn := func(t *testing.T, fixture *atesting.Fixture) {
		testComponentsPresence(context.Background(), fixture,
			[]componentPresenceDefinition{
				{"agentbeat", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
			},
			[]componentPresenceDefinition{
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			})
	}

	for _, startVersion := range versionList {
		// feature supported from 9.0.0
		if startVersion.Less(*minVersion) {
			continue
		}

		unprivilegedAvailable := false
		if upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			unprivilegedAvailable = true
		}

		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			testStandaloneUpgradeFlavorCheck(t, startVersion, define.Version(), false, false, checkFn)
		})
		if unprivilegedAvailable {
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgradeFlavorCheck(t, startVersion, define.Version(), true, false, checkFn)
			})
		}
	}
}

func TestStandaloneUpgrade_Flavor_Servers(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_9_0_0_SNAPSHOT
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if currentVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	checkFn := func(t *testing.T, fixture *atesting.Fixture) {
		testComponentsPresence(context.Background(), fixture,
			[]componentPresenceDefinition{
				{"agentbeat", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
			[]componentPresenceDefinition{})
	}

	for _, startVersion := range versionList {
		// feature supported from 9.0.0
		if startVersion.Less(*minVersion) {
			continue
		}

		unprivilegedAvailable := false
		if upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			unprivilegedAvailable = true
		}

		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			testStandaloneUpgradeFlavorCheck(t, startVersion, define.Version(), false, true, checkFn)
		})
		if unprivilegedAvailable {
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgradeFlavorCheck(t, startVersion, define.Version(), true, true, checkFn)
			})
		}
	}
}

func TestStandaloneUpgrade_Flavor_UpgradeFromUnflavored(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_9_0_0_SNAPSHOT
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if currentVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	checkFn := func(t *testing.T, fixture *atesting.Fixture) {
		testComponentsPresence(context.Background(), fixture,
			[]componentPresenceDefinition{
				{"agentbeat", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
			[]componentPresenceDefinition{})
	}

	for _, startVersion := range versionList {
		// feature supported from 9.0.0
		if !startVersion.Less(*minVersion) {
			continue
		}

		unprivilegedAvailable := false
		if upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			unprivilegedAvailable = true
		}

		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			testStandaloneUpgradeFlavorCheck(t, startVersion, define.Version(), false, false, checkFn)
		})
		if unprivilegedAvailable {
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgradeFlavorCheck(t, startVersion, define.Version(), true, false, checkFn)
			})
		}
	}
}

func testStandaloneUpgradeFlavorCheck(t *testing.T, startVersion *version.ParsedSemVer, endVersion string, unprivileged bool, hasServers bool, flavorCheck func(t *testing.T, f *atesting.Fixture)) {
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	startFixture, err := atesting.NewFixture(
		t,
		startVersion.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
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

	upgradeOpts := []upgradetest.UpgradeOpt{
		upgradetest.WithUnprivileged(unprivileged),
	}
	if hasServers {
		upgradeOpts = append(upgradeOpts, upgradetest.WithServers())
	}

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradeOpts...)
	assert.NoError(t, err)

	flavorCheck(t, endFixture)
}
