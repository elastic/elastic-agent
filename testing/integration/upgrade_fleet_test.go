// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"os"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// TestFleetManagedUpgrade tests that the build under test can retrieve an action from
// Fleet and perform the upgrade. It does not need to test all the combinations of
// versions as the standalone tests already perform those tests and would be redundant.
func TestFleetManagedUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)
	err = startFixture.Prepare(ctx)
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// Upgrade to a different build but of the same version (always a snapshot).
	// In the case there is not a different build then the test is skipped.
	// Fleet doesn't allow a downgrade to occur, so we cannot go to a lower version.
	sameVersion := define.Version()
	if !strings.HasSuffix(sameVersion, "-SNAPSHOT") {
		sameVersion += "-SNAPSHOT"
	}
	endFixture, err := atesting.NewFixture(
		t,
		sameVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)
	err = endFixture.Prepare(ctx)
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	if startVersionInfo.Binary.String() == endVersionInfo.Binary.String() && startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Build under test is the same as the build from the artifacts repository (version: %s) [commit: %s]", startVersionInfo.Binary.String(), startVersionInfo.Binary.Commit)
	}

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...", define.Version(), endVersionInfo.Binary.String())

	testUpgradeFleetManagedElasticAgent(ctx, t, info, startFixture, endFixture, defaultPolicy())
}

// The test:
//
//	[x] download the "downgradeTo" from artefacts api
//	[x] setup the Go httptest.Server to serve the agent artefacts
//	[x] block the connections to artefacts.elastic.co using iptables
//	[x] check the connection is indeed blocked
//	[x] double check the stack is still reachable
//	[ ] configure the policy to use the custom artifactsAPI server
//	[ ] install / upgrade the agent
func TestFleetManagedAirGapedUpgrade(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		// The test uses iptables to simulate the air-gaped environment.
		OS:      []define.OS{{Type: define.Linux}},
		Isolate: true,
		Local:   false, // requires Agent installation
		Sudo:    true,  // requires Agent installation
	})

	ctx, _ := testcontext.WithDeadline(
		t, context.Background(), time.Now().Add(10*time.Minute))

	artifactAPI := tools.NewArtifactAPIClient()
	latest, err := artifactAPI.GetLatestSnapshotVersion(ctx, t)
	require.NoError(t, err, "could not fetch latest version from artifacts API")

	// We need to prepare it first because it'll download the artifact and it
	// has to happen before we block the artifacts API IPs.
	// The test does not need a fixture, but testUpgradeFleetManagedElasticAgent
	// uses it to get some information about the agent version.
	upgradeTo, err := atesting.NewFixture(
		t,
		latest.String(),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)
	err = upgradeTo.Prepare(ctx)
	require.NoError(t, err)

	s := newArtifactsServer(ctx, t, latest.String())
	_ = s
	host := "artifacts.elastic.co"
	AirGap(nil, host)

	rctx, _ := context.WithTimeout(ctx, time.Second)
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, "https://"+host, nil)
	_, err = http.DefaultClient.Do(req)
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"request to %q should have failed, iptables rules should have blocked it")

	_, err = stack.ESClient.Info()
	require.NoErrorf(t, err,
		"failed to interact with ES after blocking %q through iptables", host)
	_, _, err = stack.KibanaClient.Request(http.MethodGet, "/api/status",
		nil, nil, nil)
	require.NoErrorf(t, err,
		"failed to interact with Kibana after blocking %q through iptables", host)

	// =========================================================================
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...",
		define.Version(), latest)

	policy := defaultPolicy()
	policy.DownloadSourceID = s.URL + "/downloads/beats/elastic-agent/"
	testUpgradeFleetManagedElasticAgent(ctx, t, stack, fixture, upgradeTo, policy)
}

func testUpgradeFleetManagedElasticAgent(
	ctx context.Context,
	t *testing.T,
	info *define.Info,
	startFixture *atesting.Fixture,
	// TODO: remove it and receive only the needed info about the target version.
	endFixture *atesting.Fixture,
	policy kibana.AgentPolicy) {

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)
	startParsedVersion, err := version.ParseVersion(startVersionInfo.Binary.String())
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)

	kibClient := info.KibanaClient
	t.Log("Creating Agent policy...")
	policyResp, err := kibClient.CreatePolicy(ctx, policy)
	require.NoError(t, err, "failed creating policy")

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentApiKeyReq)
	require.NoError(t, err, "failed creating enrollment API key")

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(kibClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	t.Log("Installing Elastic Agent...")
	var nonInteractiveFlag bool
	if upgradetest.Version_8_2_0.Less(*startParsedVersion) {
		nonInteractiveFlag = true
	}
	installOpts := atesting.InstallOpts{
		NonInteractive: nonInteractiveFlag,
		Force:          true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerURL,
			EnrollmentToken: enrollmentToken.APIKey,
		},
	}
	output, err := startFixture.Install(ctx, &installOpts)
	require.NoError(t, err, "failed to install start agent [output: %s]", string(output))
	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent through Fleet Server...")
		assert.NoError(t, fleettools.UnEnrollAgent(info.KibanaClient, policy.ID))
	})

	t.Log("Waiting for Agent to be correct version and healthy...")
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	t.Log("Waiting for enrolled Agent status to be online...")
	require.Eventually(t, check.FleetAgentStatus(t, kibClient, policy.ID, "online"), 2*time.Minute, 10*time.Second, "Agent status is not online")

	t.Logf("Upgrading from version %q to version %q...", startParsedVersion, endVersionInfo.Binary.String())
	err = fleettools.UpgradeAgent(kibClient, policy.ID, endVersionInfo.Binary.String(), true)
	require.NoError(t, err)

	t.Log("Waiting from upgrade details to show up in Fleet")
	hostname, err := os.Hostname()
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		agent, err := fleettools.GetAgentByPolicyIDAndHostnameFromList(kibClient, policy.ID, hostname)
		return err == nil && agent.UpgradeDetails != nil

	}, 5*time.Minute, time.Second)

	// wait for the watcher to show up
	t.Logf("Waiting for upgrade watcher to start...")
	err = upgradetest.WaitForWatcher(ctx, 5*time.Minute, 10*time.Second)
	require.NoError(t, err)
	t.Logf("Upgrade watcher started")

	// wait for the agent to be healthy and correct version
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	t.Log("Waiting for enrolled Agent status to be online...")
	require.Eventually(t, check.FleetAgentStatus(t, kibClient, policy.ID, "online"), 10*time.Minute, 15*time.Second, "Agent status is not online")

	// wait for version
	require.Eventually(t, func() bool {
		t.Log("Getting Agent version...")
		newVersion, err := fleettools.GetAgentVersion(kibClient, policy.ID)
		if err != nil {
			t.Logf("error getting agent version: %v", err)
			return false
		}
		return endVersionInfo.Binary.Version == newVersion
	}, 5*time.Minute, time.Second)

	t.Logf("Waiting for upgrade watcher to finish...")
	err = upgradetest.WaitForNoWatcher(ctx, 2*time.Minute, 10*time.Second, 1*time.Minute+15*time.Second)
	require.NoError(t, err)
	t.Logf("Upgrade watcher finished")

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = upgradetest.CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary)
	assert.NoError(t, err)
}

func defaultPolicy() kibana.AgentPolicy {
	policyUUID := uuid.New().String()

	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	return createPolicyReq
}

func AirGap(t *testing.T, host string) {
	ips, err := net.LookupIP(host)
	if err != nil {
		panic(err)
	}

	// iptables -A OUTPUT -j DROP -d IP
	t.Logf("found %v IPs for %q, blockingn them...", ips, host)
	var toCleanUp [][]string
	const iptables = "iptables"
	const ip6tables = "ip6tables"
	var cmd string
	for _, ip := range ips {
		cmd = iptables
		if ip.To4() == nil {
			cmd = ip6tables
		}
		args := []string{"-A", "OUTPUT", "-j", "DROP", "-d", ip.String()}

		out, err := exec.Command(
			cmd, args...).
			CombinedOutput()
		if err != nil {
			fmt.Println("FAILED:", cmd, args)
			fmt.Println(string(out))
		}
		t.Logf("added iptables rule %v", args[1:])
		toCleanUp = append(toCleanUp, append([]string{cmd, "-D"}, args[1:]...))

		// Just in case someone executes the test locally.
		t.Logf("use \"%s -D %s\" to remove it", cmd, args[1:])
	}
	t.Cleanup(func() {
		for _, c := range toCleanUp {
			cmd := c[0]
			args := c[1:]

			out, err := exec.Command(
				cmd, args...).
				CombinedOutput()
			if err != nil {
				fmt.Println("clean up FAILED:", cmd, args)
				fmt.Println(string(out))
			}
		}
	})
}

//	func TestManual(t *testing.T) {
//		ctx, _ := testcontext.WithDeadline(
//			t, context.Background(), time.Now().Add(10*time.Minute))
//
//		artifactAPI := tools.NewArtifactAPIClient()
//		latest, err := artifactAPI.GetLatestSnapshotVersion(ctx, t)
//		require.NoError(t, err, "could not fetch latest version from artifacts API")
//
//		s := newArtifactsServer(ctx, t, latest.String())
//		fmt.Println(s.URL)
//		host := "artifacts.elastic.co"
//		AirGap(nil, host)
//
//		rctx, _ := context.WithTimeout(ctx, 5*time.Second)
//		req, err := http.NewRequestWithContext(rctx, http.MethodGet, "https://"+host, nil)
//		_, err = http.DefaultClient.Do(req)
//		fmt.Println("req err:", err)
//		require.ErrorIs(t, err, context.DeadlineExceeded,
//			"request to %q should have failed, iptables rules should block it")
//
//		wg := sync.WaitGroup{}
//		wg.Add(1)
//		wg.Wait()
//	}

func newArtifactsServer(ctx context.Context, t *testing.T, version string) *httptest.Server {
	fileServerDir := t.TempDir()
	downloadAt := filepath.Join(fileServerDir, "downloads", "beats", "elastic-agent")
	err := os.MkdirAll(downloadAt, 0700)
	require.NoError(t, err, "could not create directory structure for file server")

	fetcher := atesting.ArtifactFetcher()
	fr, err := fetcher.Fetch(ctx, runtime.GOOS, runtime.GOARCH, version)
	require.NoErrorf(t, err, "could not prepare fetcher to download agent %s",
		version)
	err = fr.Fetch(ctx, t, downloadAt)
	require.NoError(t, err, "could not download agent %s", version)

	// dl, err := os.ReadDir(downloadAt)
	// require.NoError(t, err)
	// fmt.Println("files in ", downloadAt)
	// for _, d := range dl {
	// 	fmt.Println("\t", d.Name())
	// }

	fs := http.FileServer(http.Dir(fileServerDir))
	fmt.Println("fileServerDir:", fileServerDir)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.10.2-linux-x86_64.tar.gz
		fs.ServeHTTP(w, r)
	}))

}
