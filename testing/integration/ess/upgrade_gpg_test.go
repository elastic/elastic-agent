// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/pgptest"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgradeWithGPGFallback(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_8_10_0_SNAPSHOT
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if currentVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// Upgrade to an old build of the same version.
	endFixture, err := atesting.NewFixture(
		t,
		upgradetest.EnsureSnapshot(define.Version()),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	if startVersionInfo.Binary.String() == endVersionInfo.Binary.String() &&
		startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Build under test is the same as the build from the artifacts repository (version: %s) [commit: %s]",
			startVersionInfo.Binary.String(), startVersionInfo.Binary.Commit)
	}

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), endVersionInfo.Binary.String())

	defaultPGP := release.PGP()
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
		// passing "" as source URI is a hack to disable the --source-uri argument pointing at the endFixture srcPackage location
		// this test needs the agent to download the real thing from artifacts.elastic.co so empty string.
		// We need to download the same file from the same url and  use that as end fixture
		// or we need a way to disable the commit hash check (in this case the upgrade can be verified just with the
		// version string)
		upgradetest.WithSourceURI(""),
		upgradetest.WithCustomPGP(customPGP),
		upgradetest.WithSkipVerify(false))
	require.NoError(t, err, "perform upgrade failed")
}

func TestStandaloneUpgradeWithGPGFallbackOneRemoteFailing(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_8_10_0_SNAPSHOT
	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if currentVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Upgrade to an old build.
	// This is probably a way of getting a signed package
	upgradeToVersion, err := upgradetest.PreviousMinor()
	require.NoError(t, err)
	var fetcher atesting.Fetcher

	// FIXME: this is a hack, PreviousMinor() uses a version.ParsedSemVer internally and that's what we should use for the snapshot check
	// We need to distinguish between snapshots and released versions and use the appropriate fetcher
	if upgradeToVersion.IsSnapshot() {
		// it's a snapshot, use the artifact fetcher
		fetcher = atesting.ArtifactFetcher()
	} else {
		// it's a released version, use httpFetcher
		// this fetcher will literally pull the package from the default elastic agent download URL
		fetcher = atesting.NewHttpFetcher()
	}

	endFixture, err := atesting.NewFixture(
		t,
		upgradeToVersion.String(),
		atesting.WithFetcher(fetcher),
	)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), upgradeToVersion)

	defaultPGP := release.PGP()
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
		// passing "" as source URI is a hack to disable the --source-uri argument pointing at the endFixture srcPackage location
		// this test needs the agent to download the real thing from artifacts.elastic.co so empty string.
		// We need to download the same file from the same url and  use that as end fixture
		// or we need a way to disable the commit hash check (in this case the upgrade can be verified just with the
		// version string)
		upgradetest.WithSourceURI(""),
		upgradetest.WithCustomPGP(customPGP),
		upgradetest.WithSkipVerify(false))
	require.NoError(t, err, "perform upgrade failed")
}

func TestFleetManagedUpgradeWithFleetServerPGPFallback(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.FleetUpgrade,
		Local: false,
		Sudo:  true,
	})

	if runtime.GOOS == "windows" {
		t.Skip("Skipped on windows until https://github.com/elastic/elastic-agent/issues/4913 is resolved")
	}

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()

	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	endFixture, err := atesting.NewFixture(
		t,
		upgradetest.EnsureSnapshot(define.Version()),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	if startVersionInfo.Binary.String() == endVersionInfo.Binary.String() &&
		startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Build under test is the same as the build from the artifacts repository (version: %s) [commit: %s]",
			startVersionInfo.Binary.String(), startVersionInfo.Binary.Commit)
	}

	endPkgPath, err := endFixture.SrcPackage(ctx)
	require.NoError(t, err)
	endPkg, err := os.Open(endPkgPath)
	require.NoError(t, err)
	pubKey, ascData := pgptest.Sign(t, endPkg)
	require.NoError(t, endPkg.Close())

	rootDir := t.TempDir()
	downloadDir := filepath.Join(rootDir, "downloads", "beats", "elastic-agent")
	require.NoError(t, os.MkdirAll(downloadDir, 0o755))
	pkgName := filepath.Base(endPkgPath)
	copyFile(t, endPkgPath, filepath.Join(downloadDir, pkgName))
	copyFile(t, endPkgPath+".sha512", filepath.Join(downloadDir, pkgName+".sha512"))
	require.NoError(t, os.WriteFile(filepath.Join(downloadDir, pkgName+".asc"), ascData, 0o644))

	fileServer := httptest.NewServer(http.FileServer(http.Dir(rootDir)))
	defer fileServer.Close()

	var pgpKeyRequests atomic.Int32
	apiKey, policyData := createBasicFleetPolicyData(t, "")
	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()
	handlers := &fleetservertest.Handlers{
		APIKey:    apiKey.Key,
		AgentID:   policyData.AgentID,
		CheckinFn: fleetservertest.NewHandlerCheckin(checkinWithAcker.ActionsGenerator()),
		EnrollFn:  fleetservertest.NewHandlerEnroll(policyData.AgentID, policyData.PolicyID, apiKey),
		AckFn:     fleetservertest.NewHandlerAckWithAcker(checkinWithAcker.Acker()),
		StatusFn:  fleetservertest.NewHandlerStatusHealthy(),
		PGPKeyFn: func(_ context.Context, _ *fleetservertest.Handlers, _ string) ([]byte, *fleetservertest.HTTPError) {
			pgpKeyRequests.Add(1)
			return pubKey, nil
		},
	}
	fleetServer := fleetservertest.NewServer(handlers, fleetservertest.WithTLS(), fleetservertest.WithRequestLog(t.Logf))
	defer fleetServer.Close()

	policyData.FleetHosts = []string{fleetServer.LocalhostURL}
	policyData.DownloadSSL = &fleetservertest.SSL{VerificationMode: "none"}
	policyChangeActionID := "policy-change"
	policyChange, err := fleetservertest.NewActionWithEmptyPolicyChange(policyChangeActionID, policyData)
	require.NoError(t, err)
	checkinWithAcker.AddCheckin("policy-change-token", 0, policyChange)

	out, err := startFixture.Install(ctx, &atesting.InstallOpts{
		Force:          true,
		NonInteractive: true,
		Insecure:       true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServer.LocalhostURL,
			EnrollmentToken: "anythingWillDO",
		}})
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)

	require.Eventually(t, func() bool {
		return checkinWithAcker.Acked(policyChangeActionID)
	}, 2*time.Minute, time.Second, "policy change was not acked")

	upgradeAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policyData.AgentID,
		ActionID: "upgrade",
		Type:     fleetapi.ActionTypeUpgrade,
		Data:     fmt.Sprintf(`{"version": %q, "source_uri": %q}`, endVersionInfo.Binary.String(), fileServer.URL+"/downloads/"),
	})
	require.NoError(t, err)
	checkinWithAcker.AddCheckin("upgrade-token", 0, upgradeAction)

	err = upgradetest.WaitForWatcher(ctx, 5*time.Minute, upgradetest.WatcherPollInterval)
	require.NoError(t, err, "waiting for upgrade watcher to start")

	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, upgradetest.StatusPollInterval, t)
	require.NoError(t, err, "agent did not upgrade to %s", endVersionInfo.Binary.String())
	assert.NotZero(t, pgpKeyRequests.Load(), "Fleet Server PGP key was not requested")
}
