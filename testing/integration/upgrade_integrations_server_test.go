// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"math/rand"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/ess"
	"github.com/elastic/elastic-agent/pkg/version"
)

// TestUpgradeIntegrationsServer attempts to upgrade the Integrations Server (i.e. Elastic Agent
// running it's own Fleet Server) in ECH and ensures that the upgrade succeeds.
func TestUpgradeIntegrationsServer(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: true,  // only orchestrates ECH resources
		Sudo:  false, // only orchestrates ECH resources
		FIPS:  true,  // ensures test runs against FRH ECH region
	})

	// Default ECH region is gcp-us-west2 which is the CFT region.
	echRegion := os.Getenv("TEST_INTEG_AUTH_ESS_REGION")
	if echRegion == "" {
		require.Fail(t, "ECH FRH region not configured via the TEST_INTEG_AUTH_ESS_REGION environment variable")
	}

	echApiKey, ok, err := ess.GetESSAPIKey()
	require.NoError(t, err)
	if !ok {
		t.Fatal("ECH API key missing")
	}

	// Pick a random pair of start and end versions for ECH deployment
	prov, err := ess.NewProvisioner(ess.ProvisionerConfig{
		Identifier: "it-upgrade-integrations-server",
		APIKey:     echApiKey,
		Region:     echRegion,
	})
	require.NoError(t, err)
	statefulProv, ok := prov.(*ess.StatefulProvisioner)
	require.True(t, ok)

	minStartVersion := version.NewParsedSemVer(8, 19, 0, "", "")
	startVersion, endVersion := getRandomStackVersionsPair(t, statefulProv, minStartVersion, nil)

	// Create ECH deployment with start version
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	deployment, err := prov.Create(ctx, common.StackRequest{
		ID:      "it-upgrade-integrations-server",
		Version: startVersion.String(),
	})
	require.NoError(t, err)

	// Check that deployment is ready and healthy after creation
	deployment, err = prov.WaitForReady(ctx, deployment)
	require.NoError(t, err)

	// Upgrade deployment to end version
	err = prov.Upgrade(ctx, deployment, endVersion)
	require.NoError(t, err)

	// Check that deployment is ready and healthy after upgrade
	deployment, err = prov.WaitForReady(ctx, deployment)
	require.NoError(t, err)
}

// getRandomStackVersionsPair returns an ordered pair of versions, where the first return value is less than the second. The
// returned versions are those that are available in the ECH region specified in the TEST_INTEG_AUTH_ESS_REGION environment
// variable.
func getRandomStackVersionsPair(t *testing.T, prov *ess.StatefulProvisioner, minVersion *version.ParsedSemVer, maxVersion *version.ParsedSemVer) (*version.ParsedSemVer, *version.ParsedSemVer) {
	t.Helper()

	versions, err := prov.AvailableVersions()
	require.NoError(t, err)

	sort.Slice(versions, func(i, j int) bool {
		verI := versions[i]
		verJ := versions[j]

		return verI.Less(*verJ)
	})

	// TODO: filter out versions < minVersion and > maxVersion

	var startIdx, endIdx int
	startIdx = rand.Intn(len(versions) - 1)
	endIdx = startIdx + rand.Intn(len(versions)-startIdx-1) + 1

	return versions[startIdx], versions[endIdx]
}
