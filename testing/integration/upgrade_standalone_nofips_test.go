// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && !requirefips

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// This file contains upgrade tests that pertain to FIPS-capable Agent artifacts.

// TestStandaloneUpgradeFIPStoNonFIPS ensures that upgrading a FIPS-capable Agent
// to a non-FIPS-capable Agent is not permitted. The !requirefips build tag on this file
// ensures that this integration test will only run where the locally-built Agent fixture
// is not FIPS-capable.  As this is the fixture
func TestStandaloneUpgradeFIPStoNonFIPS(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: StandaloneUpgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	// parse the version we are testing
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	// 9.1.0-SNAPSHOT is the minimum version we need for testing upgrading from FIPS to non-FIPS.
	if currentVersion.Less(*upgradetest.Version_9_1_0_SNAPSHOT) {
		t.Skipf("Minimum version for running this test is %q, current version: %q", *upgradetest.Version_9_1_0_SNAPSHOT, currentVersion)
	}

	// Start with a FIPS-compliant Agent artifact
	fipsArtifactFetcher := atesting.ArtifactFetcher(atesting.WithArtifactFIPSOnly())

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	// Check that new (post-upgrade) Agent is FIPS-compliant
	postWatcherSuccessHook := func(ctx context.Context, endFixture *atesting.Fixture) error {
		client := endFixture.Client()
		err := client.Connect(ctx)
		if err != nil {
			return err
		}

		ver, err := client.Version(ctx)
		if err != nil {
			return err
		}

		if !ver.Fips {
			return errors.New("expected upgraded Agent to be FIPS-compliant")
		}

		return nil
	}

	for _, startVersion := range versionList {
		upgradeOpts := []upgradetest.UpgradeOpt{
			upgradetest.WithPostWatcherSuccessHook(postWatcherSuccessHook),
		}

		unprivilegedAvailable := false
		if upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			unprivilegedAvailable = true
		}
		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			upgradeOpts = append(upgradeOpts, upgradetest.WithUnprivileged(false))
			testStandaloneUpgrade(t, startVersion, define.Version(), fipsArtifactFetcher, upgradeOpts...)
		})
		if unprivilegedAvailable {
			upgradeOpts = append(upgradeOpts, upgradetest.WithUnprivileged(true))
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgrade(t, startVersion, define.Version(), fipsArtifactFetcher, upgradeOpts...)
			})
		}
	}
}
