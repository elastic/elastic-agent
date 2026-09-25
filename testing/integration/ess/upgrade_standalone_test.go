// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
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

// TestStandaloneUpgrade runs the privileged half of the standalone upgrade matrix.
// The unprivileged half lives in TestStandaloneUpgradeUnprivileged so that each half runs
// in its own CI group (and on its own VM), halving the wall-clock time of the longest test.
func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.StandaloneUpgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		// Pre-9.3 elastic-agent releases do not have "windows-binary-arm64" in
		// their internal/pkg/agent/application/upgrade/artifact packageArchMap
		// (added by PR #11673), so they cannot fetch the windows/arm64 upgrade
		// artifact. Until the start-version list excludes pre-9.3, skip this
		// matrix entry on windows/arm64.
		SkipOS: []define.OS{{Type: define.Windows, Arch: define.ARM64}},
	})

	testStandaloneUpgradeMatrix(t, false)
}

// TestStandaloneUpgradeUnprivileged runs the unprivileged half of the standalone upgrade
// matrix, see TestStandaloneUpgrade.
func TestStandaloneUpgradeUnprivileged(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.StandaloneUpgradeUnprivileged,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		// See TestStandaloneUpgrade.
		SkipOS: []define.OS{{Type: define.Windows, Arch: define.ARM64}},
	})

	testStandaloneUpgradeMatrix(t, true)
}

// testStandaloneUpgradeMatrix upgrades from every version in the upgrade test version list
// to the version under test, either privileged or unprivileged. Start versions that do not
// support unprivileged mode are skipped when unprivileged is true.
func testStandaloneUpgradeMatrix(t *testing.T, unprivileged bool) {
	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	mode := "privileged"
	if unprivileged {
		mode = "unprivileged"
	}

	for _, startVersion := range versionList {
		if unprivileged && !upgradetest.SupportsUnprivileged(startVersion, endVersion) {
			t.Logf("Skipping %s to %s (unprivileged): start version does not support unprivileged mode", startVersion, define.Version())
			continue
		}
		t.Run(fmt.Sprintf("Upgrade %s to %s (%s)", startVersion, define.Version(), mode), func(t *testing.T) {
			testStandaloneUpgrade(t, startVersion, define.Version(), atesting.ArtifactFetcher(), upgradetest.WithUnprivileged(unprivileged))
		})
	}
}

func testStandaloneUpgrade(t *testing.T, startVersion *version.ParsedSemVer, endVersion string, fetcher atesting.Fetcher, upgradeOpts ...upgradetest.UpgradeOpt) {
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
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
