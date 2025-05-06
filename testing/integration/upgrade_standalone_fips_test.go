// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// This file contains upgrade tests that pertain to FIPS-capable Agent artifacts.

// TestStandaloneUpgradeFIPStoFIPS ensures that upgrading a FIPS-capable Agent
// results in the new (post-upgrade) Agent to also be FIPS-capable.
func TestStandaloneUpgradeFIPStoFIPS(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: StandaloneUpgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
		// FIPS: true // TODO: uncomment when https://github.com/elastic/elastic-agent/pull/8083 is merged
	})

	// parse the version we are testing
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	// We need to end the upgrade at a FIPS-capable version.
	// We need to start the upgrade from a FIPS-capable version
	if !isFIPSCapableVersion(currentVersion) {
		t.Skipf(
			"Minimum end version of FIPS-capable Agent for running this test is either %q or %q, current start version: %q",
			*upgradetest.Version_8_19_0_SNAPSHOT,
			*upgradetest.Version_9_1_0_SNAPSHOT,
			currentVersion,
		)
	}

	// Start with a FIPS-capable Agent artifact
	fipsArtifactFetcher := atesting.ArtifactFetcher(atesting.WithArtifactFIPSOnly())

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	// Check that new (post-upgrade) Agent is also FIPS-capable
	postWatcherSuccessHook := upgradetest.PostUpgradeAgentIsFIPSCapable

	for _, startVersion := range versionList {
		// We need to start the upgrade from a FIPS-capable version
		if !isFIPSCapableVersion(startVersion) {
			t.Logf(
				"Minimum start version of FIPS-capable Agent for running this test is either %q or %q, current start version: %q",
				*upgradetest.Version_8_19_0_SNAPSHOT,
				*upgradetest.Version_9_1_0_SNAPSHOT,
				startVersion,
			)
			continue
		}

		upgradeOpts := []upgradetest.UpgradeOpt{
			upgradetest.WithPostWatcherSuccessHook(postWatcherSuccessHook),
		}

		unprivilegedAvailable := false
		if upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			unprivilegedAvailable = true
		}
		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			upgradeOpts = append(upgradeOpts, upgradetest.WithUnprivileged(false))
			testStandaloneUpgradeSucceeded(t, startVersion, define.Version(), fipsArtifactFetcher, upgradeOpts...)
		})
		if unprivilegedAvailable {
			upgradeOpts = append(upgradeOpts, upgradetest.WithUnprivileged(true))
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgradeSucceeded(t, startVersion, define.Version(), fipsArtifactFetcher, upgradeOpts...)
			})
		}
	}
}

// TestStandaloneUpgradeFIPStoNonFIPS ensures that a FIPS-capable Agent
// cannot be upgraded to a non-FIPS-capable Agent.
func TestStandaloneUpgradeFIPStoNonFIPS(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: StandaloneUpgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	// Start with a FIPS-capable Agent artifact
	fipsArtifactFetcher := atesting.ArtifactFetcher(atesting.WithArtifactFIPSOnly())

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	for _, startVersion := range versionList {
		// We need to start the upgrade from a FIPS-capable version
		if !isFIPSCapableVersion(startVersion) {
			t.Logf(
				"Minimum start version of FIPS-capable Agent for running this test is either %q or %q, current start version: %q",
				*upgradetest.Version_8_19_0_SNAPSHOT,
				*upgradetest.Version_9_1_0_SNAPSHOT,
				startVersion,
			)
			continue
		}

		unprivilegedAvailable := false
		if upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			unprivilegedAvailable = true
		}
		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			upgradeOpts := []upgradetest.UpgradeOpt{upgradetest.WithUnprivileged(false)}
			testStandaloneUpgradeFailed(t, startVersion, define.Version(), fipsArtifactFetcher, upgrade.ErrFipsToNonFips, upgradeOpts...)
		})
		if unprivilegedAvailable {
			upgradeOpts := []upgradetest.UpgradeOpt{upgradetest.WithUnprivileged(true)}
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgradeFailed(t, startVersion, define.Version(), fipsArtifactFetcher, upgrade.ErrFipsToNonFips, upgradeOpts...)
			})
		}
	}
}

func isFIPSCapableVersion(ver *version.ParsedSemVer) bool {
	// Versions prior to 8.19.0-SNAPSHOT are not FIPS-capable
	if ver.Less(*upgradetest.Version_8_19_0_SNAPSHOT) {
		return false
	}

	// The 9.0.x versions are not FIPS-capable
	if ver.Major() == upgradetest.Version_9_0_0_SNAPSHOT.Major() &&
		ver.Minor() == upgradetest.Version_9_0_0_SNAPSHOT.Minor() {
		return false
	}

	// All versions starting with 9.1.0-SNAPSHOT are FIPS-capable
	return true
}
