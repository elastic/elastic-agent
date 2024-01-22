// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
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

const (
	artifactElasticAgentProject = "elastic-agent-package"
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

	aac := tools.NewArtifactAPIClient()
	latestSnapshotVersion, err := aac.GetLatestSnapshotVersion(ctx, t)
	require.NoError(t, err)

	// start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)
	startVersion, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// We need to find a build which is not the latest (so, we can make sure we address it by a build ID
	// in the version prefix, e.g. x.y.z-SNAPSHOT-<buildid>) and does not have the same commit hash
	// as the currently running binary (so, we don't have a file system collision).
	// Multiple builds can have different IDs but the same commit hash.
	preReleaseVersion := latestSnapshotVersion.VersionWithPrerelease()
	resp, err := aac.GetBuildsForVersion(ctx, preReleaseVersion)
	require.NoError(t, err)

	if len(resp.Builds) < 2 {
		t.Skipf("need at least 2 builds in the version %s", latestSnapshotVersion.VersionWithPrerelease())
		return
	}

	var upgradeVersionString string
	for _, buildID := range resp.Builds[1:] {
		details, err := aac.GetBuildDetails(ctx, preReleaseVersion, buildID)
		require.NoError(t, err)
		if details.Build.Projects[artifactElasticAgentProject].CommitHash != startVersion.Binary.Commit {
			upgradeVersionString = buildID
			break
		}
	}

	if upgradeVersionString == "" {
		t.Skipf("there is no other build with a non-matching commit hash in the given version %s", latestSnapshotVersion.VersionWithPrerelease())
		return
	}

	buildFragments := strings.Split(upgradeVersionString, "-")
	require.Lenf(t, buildFragments, 2, "version %q returned by artifact api is not in format <version>-<buildID>", upgradeVersionString)
	endParsedVersion := version.NewParsedSemVer(
		latestSnapshotVersion.Major(),
		latestSnapshotVersion.Minor(),
		latestSnapshotVersion.Patch(),
		latestSnapshotVersion.Prerelease(),
		buildFragments[1],
	)

	// Upgrade to the specific build.
	endFixture, err := atesting.NewFixture(
		t,
		endParsedVersion.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), endParsedVersion.String())

	// We pass the upgradetest.WithDisableUpgradeWatcherUpgradeDetailsCheck option here because the endFixture
	// is fetched from the artifacts API and it may not contain changes in the Upgrade Watcher whose effects are
	// being asserted upon in upgradetest.PerformUpgrade.
	// TODO: Stop passing this option and remove these comments once 8.13.0 has been released.
	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradetest.WithDisableUpgradeWatcherUpgradeDetailsCheck())
	assert.NoError(t, err)
}
