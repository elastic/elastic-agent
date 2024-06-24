// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneDowngradeToSpecificSnapshotBuild(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	// support for upgrading to a specific snapshot build was not
	// added until 8.9.
	minVersion := upgradetest.Version_8_9_0_SNAPSHOT
	pv, err := version.ParseVersion(define.Version())
	if pv.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	latestSnapshotVersion, err := version.ParseVersion(upgradetest.EnsureSnapshot(define.Version()))
	require.NoError(t, err)

	// start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	startVersion, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// We need to find a build which is not the latest (so, we can make sure we address it by a build ID
	// in the version prefix, e.g. x.y.z-SNAPSHOT-<buildid>) and does not have the same commit hash
	// as the currently running binary (so, we don't have a file system collision).
	// Multiple builds can have different IDs but the same commit hash.
	preReleaseVersion := latestSnapshotVersion.VersionWithPrerelease()
	aac := tools.NewArtifactAPIClient()
	buildInfo, err := aac.FindBuild(ctx, preReleaseVersion, startVersion.Binary.Commit, 1)
	if errors.Is(err, tools.ErrBuildNotFound) {
		t.Skipf("there is no other build with a non-matching commit hash in the given version %s", latestSnapshotVersion.VersionWithPrerelease())
		return
	}
	require.NoError(t, err)

	// Upgrade to the specific build.
	t.Logf("found build %q available for testing", buildInfo.Build.BuildID)
	endVersion := versionWithBuildID(t, latestSnapshotVersion, buildInfo.Build.BuildID)
	endFixture, err := atesting.NewFixture(
		t,
		endVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), endVersion)

	// We pass the upgradetest.WithDisableUpgradeWatcherUpgradeDetailsCheck option here because the endFixture
	// is fetched from the artifacts API and it may not contain changes in the Upgrade Watcher whose effects are
	// being asserted upon in upgradetest.PerformUpgrade.
	// TODO: Stop passing this option and remove these comments once 8.13.0 has been released.
	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradetest.WithDisableUpgradeWatcherUpgradeDetailsCheck())
	assert.NoError(t, err)
}

// versionWithBuildID creates a new parsed version created from the given `initialVersion` with the given `buildID` as build metadata.
func versionWithBuildID(t *testing.T, initialVersion *version.ParsedSemVer, buildID string) string {
	buildFragments := strings.Split(buildID, "-")
	require.Lenf(t, buildFragments, 2, "version %q returned by artifact api is not in format <version>-<buildID>", buildID)
	result := version.NewParsedSemVer(
		initialVersion.Major(),
		initialVersion.Minor(),
		initialVersion.Patch(),
		initialVersion.Prerelease(),
		buildFragments[1],
	)

	return result.String()

}
