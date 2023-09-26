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

	"github.com/elastic/elastic-agent/internal/pkg/release"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgradeWithGPGFallback(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_8_10_0_SNAPSHOT
	fromVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if fromVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// Upgrade to an old build, see `BackwardTwoMinors` for why.
	upgradeToVersion, err := upgradetest.BackwardTwoMinors(define.Version())
	require.NoError(t, err)
	endFixture, err := atesting.NewFixture(
		t,
		upgradeToVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), upgradeToVersion)

	_, defaultPGP := release.PGP()
	firstSeven := string(defaultPGP[:7])
	newPgp := strings.Replace(
		string(defaultPGP),
		firstSeven,
		"abcDEFg",
		1,
	)

	customPGP := upgradetest.CustomPGP{
		PGP: newPgp,
	}

	err = upgradetest.PerformUpgrade(
		ctx, startFixture, endFixture, t,
		upgradetest.WithCustomPGP(customPGP),
		upgradetest.WithSkipVerify(false))
	assert.NoError(t, err)
}

func TestStandaloneUpgradeWithGPGFallbackOneRemoteFailing(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_8_10_0_SNAPSHOT
	fromVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if fromVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// Upgrade to an old build, see `BackwardTwoMinors` for why.
	upgradeToVersion, err := upgradetest.BackwardTwoMinors(define.Version())
	require.NoError(t, err)
	endFixture, err := atesting.NewFixture(
		t,
		upgradeToVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), upgradeToVersion)

	_, defaultPGP := release.PGP()
	firstSeven := string(defaultPGP[:7])
	newPgp := strings.Replace(
		string(defaultPGP),
		firstSeven,
		"abcDEFg",
		1,
	)

	customPGP := upgradetest.CustomPGP{
		PGP:    newPgp,
		PGPUri: "https://127.0.0.1:3456/non/existing/path",
	}

	err = upgradetest.PerformUpgrade(
		ctx, startFixture, endFixture, t,
		upgradetest.WithCustomPGP(customPGP),
		upgradetest.WithSkipVerify(false))
}
