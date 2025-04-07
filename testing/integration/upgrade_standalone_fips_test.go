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
	// TODO: introduce FIPS option for artifact fetcher
	startFixture, err := atesting.NewFixture(
		t,
		startVersion.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err, "error creating previous agent fixture")

	// Upgrade to newer version of Agent

	// Check that new (post-upgrade) Agent is also FIPS-compliant
	// TODO: check if Agent status contains information about FIPS mode
}
