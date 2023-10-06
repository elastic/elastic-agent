// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneDowngradeToSpecificSnapshotBuild(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: "upgrade-specific",
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// retrieve all the versions of agent from the artifact API
	aac := tools.NewArtifactAPIClient()
	latestSnapshotVersion, err := tools.GetLatestSnapshotVersion(ctx, t, aac)
	require.NoError(t, err)

	// get all the builds of the snapshot version (need to pass x.y.z-SNAPSHOT format)
	// 2 builds are required to be available for the test to work. This is because
	// if we upgrade to the latest build there would be no difference then passing the version
	// string without the buildid, being agent would pick that build anyway.
	// We pick the build that is 2 builds back to upgrade to, to ensure that the buildid is
	// working correctly and agent is not only picking the latest build.
	builds, err := aac.GetBuildsForVersion(ctx, latestSnapshotVersion.VersionWithPrerelease())
	require.NoError(t, err)
	if len(builds.Builds) < 2 {
		t.Skipf("not enough SNAPSHOT builds exist for version %s. Found %d", latestSnapshotVersion.VersionWithPrerelease(), len(builds.Builds))
	}

	// find the specific build to use for the test
	upgradeVersionString := builds.Builds[1]
	buildFragments := strings.Split(upgradeVersionString, "-")
	require.Lenf(t, buildFragments, 2, "version %q returned by artifact api is not in format <version>-<buildID>", upgradeVersionString)
	endParsedVersion := version.NewParsedSemVer(
		latestSnapshotVersion.Major(),
		latestSnapshotVersion.Minor(),
		latestSnapshotVersion.Patch(),
		latestSnapshotVersion.Prerelease(),
		buildFragments[1],
	)

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// Upgrade to the specific build.
	endFixture, err := atesting.NewFixture(
		t,
		endParsedVersion.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), endParsedVersion.String())

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t)
	assert.NoError(t, err)
}
