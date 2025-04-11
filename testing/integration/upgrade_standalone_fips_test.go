// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// This file contains upgrade tests that pertain to FIPS-compliant Agent artifacts.

// TestStandaloneUpgradeFIPStoFIPS ensures that upgrading a FIPS-compliant Agent
// results in the new (post-upgrade) Agent to also be FIPS-compliant.
func TestStandaloneUpgradeFIPStoFIPS(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: StandaloneUpgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	// Start with a FIPS-compliant Agent artifact
	fipsArtifactFetcher := atesting.ArtifactFetcher(atesting.WithArtifactFIPSOnly())
	startFixture, err := atesting.NewFixture(
		t,
		startVersion.String(),
		atesting.WithFetcher(fipsArtifactFetcher),
	)
	require.NoError(t, err, "error creating previous agent fixture")

	// Upgrade to newer version of Agent
	endFixture, err := define.NewFixtureFromLocalBuild(t, endVersion)
	require.NoError(t, err)

	err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t, upgradetest.WithUnprivileged(unprivileged))
	require.NoError(t, err)

	// Check that new (post-upgrade) Agent is also FIPS-compliant
	client := endFixture.Client()
	err = client.Connect(ctx)
	require.NoError(t, err)

	ver, err := client.Version(ctx)
	require.NoError(t, err)
	require.True(t, ver.Fips)
}
