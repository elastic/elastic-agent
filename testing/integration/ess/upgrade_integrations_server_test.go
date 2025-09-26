// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/ess"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// TestUpgradeIntegrationsServer attempts to upgrade the Integrations Server (i.e. Elastic Agent
// running its own Fleet Server) in ECH and ensures that the upgrade succeeds.
func TestUpgradeIntegrationsServer(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.ECHDeployment,
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

	startVersions := getUpgradeableFIPSVersions(t)
	endVersion := define.Version()

	prov, err := ess.NewProvisioner(ess.ProvisionerConfig{
		Identifier: "it-upgrade-integrations-server",
		APIKey:     echApiKey,
		Region:     echRegion,
	})
	require.NoError(t, err)
	prov.SetLogger(t)
	statefulProv, ok := prov.(*ess.StatefulProvisioner)
	require.True(t, ok)

	startVersions = filterVersionsForECH(t, startVersions, statefulProv)
	startVersions = filterVersionsForSameReleaseType(t, startVersions, endVersion)

	t.Logf("Running test cases for upgrade from versions [%v] to version [%s]", startVersions, endVersion)
	for _, startVersion := range startVersions {
		t.Logf("Running test case for upgrade from version [%s] to version [%s]...", startVersion.String(), endVersion)
		t.Run(fmt.Sprintf("%s_to_%s", startVersion.String(), endVersion), func(t *testing.T) {
			// Create ECH deployment with start version
			t.Logf("Creating ECH deployment with version [%s] in region [%s]", startVersion.String(), echRegion)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			deployment, err := statefulProv.Create(ctx, common.StackRequest{
				ID:      "it-upgrade-integrations-server",
				Version: startVersion.String(),
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				if deployment.ID == "" {
					// Nothing to cleanup
					return
				}

				if t.Failed() {
					cleanupDelay := 1 * time.Minute
					t.Logf("Cleaning up ECH deployment [%s] in region [%s] after [%s]", deployment.ID, echRegion, cleanupDelay)
					<-time.After(cleanupDelay)
				} else {
					t.Logf("Cleaning up ECH deployment [%s] in region [%s]", deployment.ID, echRegion)
				}

				err = prov.Delete(context.Background(), deployment)
				require.NoError(t, err, "failed to delete deployment after test")
			})

			// Check that deployment is ready and healthy after creation
			t.Logf("Waiting for ECH deployment [%s] in region [%s] to be ready and healthy after creation", deployment.ID, echRegion)
			deployment, err = prov.WaitForReady(context.Background(), deployment)
			require.NoError(t, err)

			// Upgrade deployment to end version
			t.Logf("Upgrading ECH deployment [%s] in region [%s] from version [%s] to [%s]", deployment.ID, echRegion, startVersion.String(), endVersion)
			err = prov.Upgrade(context.Background(), deployment, endVersion)
			require.NoError(t, err)
			deployment.Version = endVersion

			// Check that deployment is ready and healthy after upgrade
			t.Logf("Waiting for ECH deployment [%s] in region [%s] to be ready and healthy after upgrade", deployment.ID, echRegion)
			deployment, err = prov.WaitForReady(context.Background(), deployment)
			require.NoError(t, err)
		})
	}
}

// getUpgradeableFIPSVersions returns stack versions to use as the start version for an upgrade.
func getUpgradeableFIPSVersions(t *testing.T) version.SortableParsedVersions {
	versions, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err, "could not get upgradable versions")

	filteredVersions := make([]*version.ParsedSemVer, 0)
	for _, ver := range versions {
		// Filter out versions that are not FIPS-capable
		if !isFIPSCapableVersion(ver) {
			continue
		}

		filteredVersions = append(filteredVersions, ver)
	}

	sortedVers := version.SortableParsedVersions(filteredVersions)
	sort.Sort(sortedVers)
	return sortedVers
}

func filterVersionsForECH(t *testing.T, versions []*version.ParsedSemVer, echProv *ess.StatefulProvisioner) []*version.ParsedSemVer {
	echVersions, err := echProv.AvailableVersions()
	require.NoError(t, err)

	filteredVersions := make([]*version.ParsedSemVer, 0)
	for _, ver := range versions {
		if isVersionInList(ver, echVersions) {
			filteredVersions = append(filteredVersions, ver)
		}
	}

	return filteredVersions
}

func isVersionInList(candidateVersion *version.ParsedSemVer, allowedVersions []*version.ParsedSemVer) bool {
	for _, allowedVersion := range allowedVersions {
		if allowedVersion.Equal(*candidateVersion) {
			return true
		}
	}
	return false
}

func filterVersionsForSameReleaseType(t *testing.T, versions []*version.ParsedSemVer, endVersion string) []*version.ParsedSemVer {
	endVersionParsed, err := version.ParseVersion(endVersion)
	require.NoError(t, err)
	isEndVersionSnapshot := endVersionParsed.IsSnapshot()

	filteredVersions := make([]*version.ParsedSemVer, 0)
	for _, ver := range versions {
		if isEndVersionSnapshot && ver.IsSnapshot() {
			filteredVersions = append(filteredVersions, ver)
		} else if !isEndVersionSnapshot && !ver.IsSnapshot() {
			filteredVersions = append(filteredVersions, ver)
		}
	}

	return filteredVersions
}
