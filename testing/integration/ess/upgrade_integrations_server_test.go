// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
<<<<<<< HEAD
=======
	"runtime"
	"slices"
>>>>>>> 9547841 (Don't use non-GA snapshot versions as ECH upgrade start versions (#16866))
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

	echVersions, err := statefulProv.AvailableVersions()
	require.NoError(t, err)

	startVersions = filterStartVersionsForECH(t, startVersions, echVersions, endVersion)

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

				err = prov.Delete(context.Background(), deployment) //nolint:forbidigo // t.Context() is cancelled before cleanup runs, so a fresh Background context is required here
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

<<<<<<< HEAD
	filteredVersions := make([]*version.ParsedSemVer, 0)
	for _, ver := range versions {
		// Filter out versions that are not FIPS-capable
		if !isFIPSCapableVersion(ver) {
			continue
		}
=======
	versions = slices.DeleteFunc(versions, func(ver *version.ParsedSemVer) bool {
		return !isFIPSCapableVersion(ver, os, arch)
	})
>>>>>>> 9547841 (Don't use non-GA snapshot versions as ECH upgrade start versions (#16866))

	sortedVers := version.SortableParsedVersions(versions)
	sort.Sort(sortedVers)
	return sortedVers
}

// filterStartVersionsForECH keeps only versions that ECH can deploy and then upgrade to endVersion.
func filterStartVersionsForECH(t *testing.T, versions, echVersions []*version.ParsedSemVer, endVersion string) []*version.ParsedSemVer {
	t.Helper()
	endVersionParsed, err := version.ParseVersion(endVersion)
	require.NoError(t, err)

	isAvailableInECH := func(ver *version.ParsedSemVer) bool {
		return slices.ContainsFunc(echVersions, func(echVer *version.ParsedSemVer) bool {
			return echVer.Equal(*ver)
		})
	}

	return slices.DeleteFunc(slices.Clone(versions), func(ver *version.ParsedSemVer) bool {
		if !isAvailableInECH(ver) || ver.IsSnapshot() != endVersionParsed.IsSnapshot() {
			return true
		}
		// ECH's upgrade path check (ElasticsearchVersionCompatibility) strips the SNAPSHOT tag from
		// the source version and checks whether the bare version number appears in the target's
		// rolling_upgrade_compatible_versions list, which only contains GA-released versions.
		// A SNAPSHOT source whose GA equivalent (e.g. 9.4.8 for 9.4.8-SNAPSHOT) has not been
		// released yet is rejected.
		return ver.IsSnapshot() && !isAvailableInECH(version.NewParsedSemVer(ver.Major(), ver.Minor(), ver.Patch(), "", ""))
	})
}
