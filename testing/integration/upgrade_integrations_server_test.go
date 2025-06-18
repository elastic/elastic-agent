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
// running its own Fleet Server) in ECH and ensures that the upgrade succeeds.
func TestUpgradeIntegrationsServer(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: true,  // only orchestrates ECH resources
		Sudo:  false, // only orchestrates ECH resources
		FIPS:  true,  // ensures test runs against FRH ECH region
	})

	// Default ECH region is gcp-us-west2 which is the CFT region.
	echRegion := os.Getenv("ESS_REGION")
	if echRegion == "" {
		echRegion = "gcp-us-west2"
	}

	echApiKey := os.Getenv("EC_API_KEY")
	if echApiKey == "" {
		t.Fatal("ECH API key missing")
	}

	// Pick a random pair of start and end versions for ECH deployment
	prov, err := ess.NewProvisioner(ess.ProvisionerConfig{
		Identifier: "it-upgrade-integrations-server",
		APIKey:     echApiKey,
		Region:     echRegion,
	})
	require.NoError(t, err)
	prov.SetLogger(t)
	statefulProv, ok := prov.(*ess.StatefulProvisioner)
	require.True(t, ok)

	minStartVersion := version.NewParsedSemVer(8, 19, 0, "", "")
	startVersion, endVersion := getRandomStackVersionsPair(t, statefulProv, minStartVersion, nil)

	// Create ECH deployment with start version
	t.Logf("Creating ECH deployment with version [%s] in region [%s]", startVersion.String(), echRegion)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	deployment, err := prov.Create(ctx, common.StackRequest{
		ID:      "it-upgrade-integrations-server",
		Version: startVersion.String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if deployment.ID != "" {
			err = prov.Delete(context.Background(), deployment)
			require.NoError(t, err, "failed to delete deployment after test")
		}
	})

	// Check that deployment is ready and healthy after creation
	t.Logf("Waiting for ECH deployment [%s] in region [%s] to be ready and healthy after creation", deployment.ID, echRegion)
	deployment, err = prov.WaitForReady(ctx, deployment)
	require.NoError(t, err)

	// Upgrade deployment to end version
	t.Logf("Upgrading ECH deployment [%s] in region [%s] from version [%s] to [%s]", deployment.ID, echRegion, startVersion.String(), endVersion.String())
	err = prov.Upgrade(ctx, deployment, endVersion)
	require.NoError(t, err)

	// Check that deployment is ready and healthy after upgrade
	t.Logf("Waiting for ECH deployment [%s] in region [%s] to be ready and healthy after upgrade", deployment.ID, echRegion)
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
	t.Logf("available versions: %#+v", versions)

	sort.Slice(versions, func(i, j int) bool {
		verI := versions[i]
		verJ := versions[j]

		return verI.Less(*verJ)
	})

	// filter out versions < minVersion and > maxVersion
	filteredVersions := make([]*version.ParsedSemVer, 0)
	for _, ver := range versions {
		if minVersion != nil && ver.Less(*minVersion) {
			continue
		}

		if maxVersion != nil && maxVersion.Less(*ver) {
			continue
		}

		filteredVersions = append(filteredVersions, ver)
	}

	t.Logf("filtered versions: %#+v", filteredVersions)

	if len(filteredVersions) < 2 {
		t.Fatalf("not enough versions available to generate start and end version pair for upgrade: %d", len(filteredVersions))
	}

	var startIdx, endIdx int
	startIdx = rand.Intn(len(filteredVersions) - 1)
	endIdx = startIdx + rand.Intn(len(filteredVersions)-1-startIdx) + 1

	t.Logf("startIdx: %d, endIdx: %d", startIdx, endIdx)

	return filteredVersions[startIdx], filteredVersions[endIdx]
}
