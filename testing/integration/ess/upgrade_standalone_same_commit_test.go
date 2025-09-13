// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"path/filepath"
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

func TestStandaloneUpgradeSameCommit(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	// parse the version we are testing
	currentVersion, parseVersionErr := version.ParseVersion(define.Version())
	require.NoError(t, parseVersionErr)

	// 8.13.0-SNAPSHOT is the minimum version we need for testing upgrading with the same hash
	if currentVersion.Less(*upgradetest.Version_8_13_0_SNAPSHOT) {
		t.Skipf("Minimum version for running this test is %q, current version: %q", *upgradetest.Version_8_13_0_SNAPSHOT, currentVersion)
	}

	unprivilegedAvailable := false
	if upgradetest.SupportsUnprivileged(currentVersion) {
		unprivilegedAvailable = true
	}
	unPrivilegedString := "unprivileged"
	if !unprivilegedAvailable {
		unPrivilegedString = "privileged"
	}

	t.Run(fmt.Sprintf("Upgrade on the same version %s to %s (%s)", currentVersion, currentVersion, unPrivilegedString), func(t *testing.T) {
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
		defer cancel()

		// ensure we use the same package version
		startFixture, err := define.NewFixtureFromLocalBuild(
			t,
			currentVersion.String(),
		)
		require.NoError(t, err, "error creating start agent fixture")
		err = upgradetest.PerformUpgrade(ctx, startFixture, startFixture, t,
			upgradetest.WithUnprivileged(unprivilegedAvailable),
			upgradetest.WithDisableHashCheck(true),
		)
		// PerformUpgrade will exit after calling `elastic-agent upgrade ...` if a subsequent call to
		// `elastic-agent status` returns the running state with no upgrade details. This indicates that
		// the agent did a nop upgrade.
		assert.NoError(t, err)
	})

	t.Run(fmt.Sprintf("Upgrade on a repackaged version of agent %s (%s)", currentVersion, unPrivilegedString), func(t *testing.T) {
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Minute))
		defer cancel()

		startFixture, err := define.NewFixtureFromLocalBuild(
			t,
			currentVersion.String(),
		)
		require.NoError(t, err, "error creating start agent fixture")

		// modify the version with the "+buildYYYYMMDDHHMMSS"
		newVersionBuildMetadata := "build" + time.Now().Format("20060102150405")
		parsedNewVersion := version.NewParsedSemVer(currentVersion.Major(), currentVersion.Minor(), currentVersion.Patch(), "", newVersionBuildMetadata)

		err = startFixture.EnsurePrepared(t.Context())
		require.NoErrorf(t, err, "fixture should be prepared")

		// retrieve the compressed package file location
		srcPackage, err := startFixture.SrcPackage(t.Context())
		require.NoErrorf(t, err, "error retrieving start fixture source package")

		versionForFixture, repackagedArchiveFile, err := repackageArchive(t, srcPackage, newVersionBuildMetadata, currentVersion, parsedNewVersion)

		newPackageContainingDir := filepath.Dir(repackagedArchiveFile)
		repackagedLocalFetcher := atesting.LocalFetcher(newPackageContainingDir)

		endFixture, err := atesting.NewFixture(t, versionForFixture.String(), atesting.WithFetcher(repackagedLocalFetcher))
		require.NoErrorf(t, err, "error creating end fixture with LocalArtifactFetcher with dir %q", newPackageContainingDir)

		err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t,
			upgradetest.WithUnprivileged(unprivilegedAvailable),
			upgradetest.WithDisableHashCheck(true),
		)

		assert.NoError(t, err, "upgrade using version %s from the same commit should succeed")
	})

}
