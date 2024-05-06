// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"runtime"
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

func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	versionList, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err)
	endVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	for _, startVersion := range versionList {
		unprivilegedAvailable := true
		if runtime.GOOS != define.Linux {
			// only available on Linux at the moment
			unprivilegedAvailable = false
		}
		if unprivilegedAvailable && (startVersion.Less(*upgradetest.Version_8_13_0) || endVersion.Less(*upgradetest.Version_8_13_0)) {
			// only available if both versions are 8.13+
			unprivilegedAvailable = false
		}
		t.Run(fmt.Sprintf("Upgrade %s to %s (privileged)", startVersion, define.Version()), func(t *testing.T) {
			testStandaloneUpgrade(t, startVersion, define.Version(), false)
		})
		if unprivilegedAvailable {
			t.Run(fmt.Sprintf("Upgrade %s to %s (unprivileged)", startVersion, define.Version()), func(t *testing.T) {
				testStandaloneUpgrade(t, startVersion, define.Version(), true)
			})
		}
	}
}

func testStandaloneUpgrade(t *testing.T, startVersion *version.ParsedSemVer, endVersion string, unprivileged bool) {
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

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradetest.WithUnprivileged(unprivileged))
	assert.NoError(t, err)
}
