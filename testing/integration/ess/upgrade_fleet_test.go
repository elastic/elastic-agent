// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent/internal/pkg/acl"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/pgptest"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// TestFleetManagedUpgradeUnprivileged tests that the build under test can retrieve an action from
// Fleet and perform the upgrade as an unprivileged Elastic Agent. It does not need to test
// all the combinations of versions as the standalone tests already perform those tests and
// would be redundant.
func TestFleetManagedUpgradeUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})
	testFleetManagedUpgrade(t, info, true, false)
}

// TestFleetManagedUpgradePrivileged tests that the build under test can retrieve an action from
// Fleet and perform the upgrade as a privileged Elastic Agent. It does not need to test all
// the combinations of  versions as the standalone tests already perform those tests and
// would be redundant.
func TestFleetManagedUpgradePrivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.FleetPrivileged,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})
	testFleetManagedUpgrade(t, info, false, false)
}

func testFleetManagedUpgrade(t *testing.T, info *define.Info, unprivileged bool, fips bool, upgradeOpts ...upgradetest.UpgradeOpt) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	var startFixture *atesting.Fixture
	var err error
	if fips {
		startFixture, err = define.NewFixtureFromLocalFIPSBuild(t, define.Version())
	} else {
		startFixture, err = define.NewFixtureFromLocalBuild(t, define.Version())
	}
	require.NoError(t, err)
	err = startFixture.Prepare(ctx)
	require.NoError(t, err)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// Upgrade to a different build but of the same version (always a snapshot).
	// In the case there is not a different build then the test is skipped.
	// Fleet doesn't allow a downgrade to occur, so we cannot go to a lower version.
	endFixture, err := atesting.NewFixture(
		t,
		upgradetest.EnsureSnapshot(define.Version()),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	err = endFixture.Prepare(ctx)
	require.NoError(t, err)

	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	if startVersionInfo.Binary.String() == endVersionInfo.Binary.String() &&
		startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Build under test is the same as the build from the artifacts repository (version: %s) [commit: %s]",
			startVersionInfo.Binary.String(), startVersionInfo.Binary.Commit)
	}

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...",
		define.Version(), endVersionInfo.Binary.String())

	testUpgradeFleetManagedElasticAgent(ctx, t, info, startFixture, endFixture, defaultPolicy(), unprivileged, upgradeOpts...)
}

func TestFleetAirGappedUpgradeUnprivileged(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: integration.FleetAirgapped,
		Stack: &define.Stack{},
		// The test uses iptables to simulate the air-gaped environment.
		OS:    []define.OS{{Type: define.Linux}},
		Local: false, // Needed as the test requires Agent installation
		Sudo:  true,  // Needed as the test uses iptables and installs the Agent
	})
	testFleetAirGappedUpgrade(t, stack, true)
}

func TestFleetAirGappedUpgradePrivileged(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: integration.FleetAirgappedPrivileged,
		Stack: &define.Stack{},
		// The test uses iptables to simulate the air-gaped environment.
		OS:    []define.OS{{Type: define.Linux}},
		Local: false, // Needed as the test requires Agent installation
		Sudo:  true,  // Needed as the test uses iptables and installs the Agent
	})
	testFleetAirGappedUpgrade(t, stack, false)
}

func TestFleetUpgradeToPRBuild(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: integration.FleetUpgradeToPRBuild,
		Stack: &define.Stack{},
		OS:    []define.OS{{Type: define.Linux}}, // The test uses /etc/hosts.
		Sudo:  true,                              // The test uses /etc/hosts.
		// The test requires:
		//   - bind to port 443 (HTTPS)
		//   - changes to /etc/hosts
		//   - changes to /etc/ssl/certs
		//   - agent installation
		Local: false,
	})

	ctx := context.Background()

	// ========================= prepare from fixture ==========================
	versions, err := upgradetest.GetUpgradableVersions()
	require.NoError(t, err, "could not get upgradable versions")

	sortedVers := version.SortableParsedVersions(versions)
	sort.Sort(sort.Reverse(sortedVers))

	t.Logf("upgradable versions: %v", versions)
	var latestRelease version.ParsedSemVer
	for _, v := range versions {
		if !v.IsSnapshot() {
			latestRelease = *v
			break
		}
	}
	fromFixture, err := atesting.NewFixture(t,
		latestRelease.String())
	require.NoError(t, err, "could not create fixture for latest release")
	// make sure to download it before the test impersonates artifacts API
	err = fromFixture.Prepare(ctx)
	require.NoError(t, err, "could not prepare fromFixture")

	rootDir := t.TempDir()
	rootPair, childPair, cert := prepareTLSCerts(
		t, "artifacts.elastic.co", []net.IP{net.ParseIP("127.0.0.1")})

	// ==================== prepare to fixture from PR build ===================
	toFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "failed to get fixture with PR build")

	prBuildPkgPath, err := toFixture.SrcPackage(ctx)
	require.NoError(t, err, "could not get path to PR build artifact")

	agentPkg, err := os.Open(prBuildPkgPath)
	require.NoError(t, err, "could not open PR build artifact")

	// sign the build
	pubKey, ascData := pgptest.Sign(t, agentPkg)

	// ========================== file server ==================================
	downloadDir := filepath.Join(rootDir, "downloads", "beats", "elastic-agent")
	err = os.MkdirAll(downloadDir, 0644)
	require.NoError(t, err, "could not create download directory")

	server := startHTTPSFileServer(t, rootDir, cert)
	defer server.Close()

	// add root CA to /etc/ssl/certs. It was the only option that worked
	rootCAPath := filepath.Join("/etc/ssl/certs", "TestFleetUpgradeToPRBuild.pem")
	err = os.WriteFile(
		rootCAPath,
		rootPair.Cert, 0440)
	require.NoError(t, err, "could not write root CA to /etc/ssl/certs")
	t.Cleanup(func() {
		if err = os.Remove(rootCAPath); err != nil {
			t.Log("cleanup: could not remove root CA")
		}
	})

	// ====================== copy files to file server  ======================
	// copy the agent package
	_, filename := filepath.Split(prBuildPkgPath)
	pkgDownloadPath := filepath.Join(downloadDir, filename)
	copyFile(t, prBuildPkgPath, pkgDownloadPath)
	copyFile(t, prBuildPkgPath+".sha512", pkgDownloadPath+".sha512")

	// copy the PGP key
	gpgKeyElasticAgent := filepath.Join(rootDir, "GPG-KEY-elastic-agent")
	err = os.WriteFile(
		gpgKeyElasticAgent, pubKey, 0o644)
	require.NoError(t, err, "could not write GPG-KEY-elastic-agent to disk")

	// copy the package signature
	ascFile := filepath.Join(downloadDir, filename+".asc")
	err = os.WriteFile(
		ascFile, ascData, 0o600)
	require.NoError(t, err, "could not write agent .asc file to disk")

	defer func() {
		if !t.Failed() {
			return
		}

		prefix := fromFixture.FileNamePrefix() + "-"

		if err = os.WriteFile(filepath.Join(rootDir, prefix+"server.pem"), childPair.Cert, 0o777); err != nil {
			t.Log("cleanup: could not save server cert for investigation")
		}
		if err = os.WriteFile(filepath.Join(rootDir, prefix+"server_key.pem"), childPair.Key, 0o777); err != nil {
			t.Log("cleanup: could not save server cert key for investigation")
		}

		if err = os.WriteFile(filepath.Join(rootDir, prefix+"server_key.pem"), rootPair.Key, 0o777); err != nil {
			t.Log("cleanup: could not save rootCA key for investigation")
		}

		toFixture.MoveToDiagnosticsDir(rootCAPath)
		toFixture.MoveToDiagnosticsDir(pkgDownloadPath)
		toFixture.MoveToDiagnosticsDir(pkgDownloadPath + ".sha512")
		toFixture.MoveToDiagnosticsDir(gpgKeyElasticAgent)
		toFixture.MoveToDiagnosticsDir(ascFile)
	}()

	// ==== impersonate https://artifacts.elastic.co/GPG-KEY-elastic-agent  ====
	impersonateHost(t, "artifacts.elastic.co", "127.0.0.1")

	// ==================== prepare agent's download source ====================
	downloadSource := kibana.DownloadSource{
		Name:      "self-signed-" + uuid.Must(uuid.NewV4()).String(),
		Host:      server.URL + "/downloads/",
		IsDefault: false, // other tests reuse the stack, let's not mess things up
	}

	t.Logf("creating download source %q, using %q.",
		downloadSource.Name, downloadSource.Host)
	src, err := stack.KibanaClient.CreateDownloadSource(ctx, downloadSource)
	require.NoError(t, err, "could not create download source")
	policy := defaultPolicy()
	policy.DownloadSourceID = src.Item.ID
	t.Logf("policy %s using DownloadSourceID: %s",
		policy.ID, policy.DownloadSourceID)

	testUpgradeFleetManagedElasticAgent(ctx, t, stack, fromFixture, toFixture, policy, false)
}

func testFleetAirGappedUpgrade(t *testing.T, stack *define.Info, unprivileged bool) {
	ctx, _ := testcontext.WithDeadline(
		t, context.Background(), time.Now().Add(10*time.Minute))

	latest := define.Version()

	// We need to prepare it first because it'll download the artifact, and it
	// has to happen before we block the artifacts API IPs.
	// The test does not need a fixture, but testUpgradeFleetManagedElasticAgent
	// uses it to get some information about the agent version.
	upgradeTo, err := atesting.NewFixture(
		t,
		latest,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)
	err = upgradeTo.Prepare(ctx)
	require.NoError(t, err)

	s := newArtifactsServer(ctx, t, latest, upgradeTo.PackageFormat())
	host := "artifacts.elastic.co"
	simulateAirGapedEnvironment(t, host)

	rctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, "https://"+host, nil)
	_, err = http.DefaultClient.Do(req)
	if !(errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded)) {
		t.Fatalf(
			"request to %q should have failed, iptables rules should have blocked it",
			host)
	}

	_, err = stack.ESClient.Info()
	require.NoErrorf(t, err,
		"failed to interact with ES after blocking %q through iptables", host)
	_, body, err := stack.KibanaClient.Request(http.MethodGet, "/api/features",
		nil, nil, nil)
	require.NoErrorf(t, err,
		"failed to interact with Kibana after blocking %q through iptables. "+
			"It should not affect the connection to the stack. Host: %s, response body: %s",
		stack.KibanaClient.URL, host, body)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...",
		define.Version(), latest)

	downloadSource := kibana.DownloadSource{
		Name:      "local-air-gaped-" + uuid.Must(uuid.NewV4()).String(),
		Host:      s.URL + "/downloads/beats/elastic-agent/",
		IsDefault: false, // other tests reuse the stack, let's not mess things up
	}
	t.Logf("creating download source %q, using %q.",
		downloadSource.Name, downloadSource.Host)
	src, err := stack.KibanaClient.CreateDownloadSource(ctx, downloadSource)
	require.NoError(t, err, "could not create download source")

	policy := defaultPolicy()
	policy.DownloadSourceID = src.Item.ID

	testUpgradeFleetManagedElasticAgent(ctx, t, stack, fixture, upgradeTo, policy, unprivileged)
}

func testUpgradeFleetManagedElasticAgent(
	ctx context.Context,
	t *testing.T,
	info *define.Info,
	startFixture *atesting.Fixture,
	endFixture *atesting.Fixture,
	policy kibana.AgentPolicy,
	unprivileged bool,
	opts ...upgradetest.UpgradeOpt,
) {
	require.NoError(t, PerformManagedUpgrade(ctx, t, info, startFixture, endFixture, policy, unprivileged, opts...))
}

func PerformManagedUpgrade(
	ctx context.Context,
	t *testing.T,
	info *define.Info,
	startFixture *atesting.Fixture,
	endFixture *atesting.Fixture,
	policy kibana.AgentPolicy,
	unprivileged bool,
	opts ...upgradetest.UpgradeOpt,
) error {
	// use the passed in options to perform the upgrade
	var upgradeOpts upgradetest.UpgradeOpts
	for _, o := range opts {
		o(&upgradeOpts)
	}

	kibClient := info.KibanaClient

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	if err != nil {
		return fmt.Errorf("exec version on startFixture: %w", err)
	}
	startParsedVersion, err := version.ParseVersion(startVersionInfo.Binary.String())
	if err != nil {
		return fmt.Errorf("parsing version on startVersionInfo: %w", err)
	}
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	if err != nil {
		return fmt.Errorf("exec version on endFixture: %w", err)
	}
	endParsedVersion, err := version.ParseVersion(endVersionInfo.Binary.String())
	if err != nil {
		return fmt.Errorf("parsing version on endVersionInfo: %w", err)
	}

	if unprivileged {
		if !upgradetest.SupportsUnprivileged(startParsedVersion, endParsedVersion) {
			t.Skipf("Either starting version %s or ending version %s doesn't support --unprivileged", startParsedVersion.String(), endParsedVersion.String())
		}
	}

	if startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("target version has the same commit hash %q", endVersionInfo.Binary.Commit)
	}

	t.Log("Creating Agent policy...")
	policyResp, err := kibClient.CreatePolicy(ctx, policy)
	if err != nil {
		return fmt.Errorf("failed creating policy: %w", err)
	}

	policy = policyResp.AgentPolicy
	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentApiKeyReq)
	if err != nil {
		return fmt.Errorf("failed creating enrollment token: %w", err)
	}

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(ctx, kibClient)
	if err != nil {
		return fmt.Errorf("failed getting default Fleet Server URL: %w", err)
	}

	if !upgradeOpts.SkipInstall {
		t.Logf("Installing Elastic Agent (unprivileged: %t)...", unprivileged)
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
			Privileged: !unprivileged,
		}
		output, err := startFixture.Install(ctx, &installOpts)
		t.Logf("install start agent output:\n%s", string(output))
		if err != nil {
			return fmt.Errorf("failed to install start agent: %w", err)
		}
	}

	// start fixture gets the agent configured to use a faster watcher
	// THIS IS A HACK: we are modifying elastic-agent.yaml after enrollment because the watcher reads only that file to
	// configure itself. This is obviously not fit for production code or even guaranteed to be stable.
	if upgradeOpts.CustomWatcherCfg != "" {
		t.Log("Setting custom watcher config")
		err = startFixture.Configure(ctx, []byte("fleet.enabled: true\n"+upgradeOpts.CustomWatcherCfg))
	}

	t.Log("Waiting for Agent to be correct version and healthy...")
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	if err != nil {
		return fmt.Errorf("waiting for agent to become healthy: %w", err)
	}

	agentID, err := startFixture.AgentID(ctx)
	if err != nil {
		return fmt.Errorf("retrieving agent ID: %w", err)
	}
	t.Logf("Agent ID: %q", agentID)

	t.Log("Waiting for enrolled Agent status to be online...")
	_, err = backoff.Retry(ctx, func() (bool, error) {
		checkSuccessful := check.FleetAgentStatus(
			ctx, t, kibClient, agentID, "online")()
		if !checkSuccessful {
			return checkSuccessful, fmt.Errorf("agent status is not online")
		}
		return checkSuccessful, nil
	}, backoff.WithMaxElapsedTime(2*time.Minute), backoff.WithBackOff(backoff.NewConstantBackOff(10*time.Second)))
	if err != nil {
		return fmt.Errorf("waiting for upgraded agent to be online: %w", err)
	}

	t.Logf("Upgrading from version \"%s-%s\" to version \"%s-%s\"...",
		startParsedVersion, startVersionInfo.Binary.Commit,
		endVersionInfo.Binary.String(), endVersionInfo.Binary.Commit)
	err = fleettools.UpgradeAgent(ctx, kibClient, agentID, endVersionInfo.Binary.String(), true)
	if err != nil {
		return fmt.Errorf("requesting agent upgrade: %w", err)
	}

	t.Log("Waiting from upgrade details to show up in Fleet")
	_, err = backoff.Retry[kibana.GetAgentResponse](ctx, func() (kibana.GetAgentResponse, error) {
		agent, getAgentErr := kibClient.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
		if getAgentErr != nil {
			return agent, getAgentErr
		}
		if agent.UpgradeDetails == nil {
			return agent, fmt.Errorf("agent upgrade details is empty")
		}
		return agent, nil
	}, backoff.WithMaxElapsedTime(5*time.Minute), backoff.WithBackOff(backoff.NewConstantBackOff(time.Second)))
	if err != nil {
		return fmt.Errorf("waiting for upgrade details to show up in Fleet: %w", err)
	}

	// wait for the watcher to show up
	t.Logf("Waiting for upgrade watcher to start...")
	err = upgradetest.WaitForWatcher(ctx, 5*time.Minute, 10*time.Second)
	if err != nil {
		return fmt.Errorf("waiting for upgrade watcher to start: %w", err)
	}
	t.Logf("Upgrade watcher started")

	if upgradeOpts.PostUpgradeHook != nil {
		if err := upgradeOpts.PostUpgradeHook(); err != nil {
			return fmt.Errorf("post upgrade hook failed: %w", err)
		}
	}

	// wait for the agent to be healthy and correct version
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	if err != nil {
		return fmt.Errorf("waiting for agent to be healthy and version %s: %w", endVersionInfo.Binary.String(), err)
	}

	t.Log("Waiting for upgraded Agent status to be online...")
	_, err = backoff.Retry(ctx, func() (any, error) {
		checkSuccessful := check.FleetAgentStatus(ctx, t, kibClient, agentID, "online")()
		if !checkSuccessful {
			return checkSuccessful, fmt.Errorf("agent status is not online")
		}
		return checkSuccessful, nil
	}, backoff.WithMaxElapsedTime(10*time.Minute), backoff.WithBackOff(backoff.NewConstantBackOff(15*time.Second)))

	if err != nil {
		return fmt.Errorf("waiting for upgraded agent to be online: %w", err)
	}

	// wait for version
	_, err = backoff.Retry(ctx, func() (string, error) {
		t.Log("Getting Agent version...")
		newVersion, err := fleettools.GetAgentVersion(ctx, kibClient, agentID)
		if err != nil {
			t.Logf("error getting agent version: %v", err)
			return "", fmt.Errorf("getting agent information: %w", err)
		}
		if endVersionInfo.Binary.Version != newVersion {
			return newVersion, fmt.Errorf("agent version mismatch: got %s, want %s", newVersion, endVersionInfo.Binary.Version)
		}
		return newVersion, nil
	}, backoff.WithMaxElapsedTime(5*time.Minute), backoff.WithBackOff(backoff.NewConstantBackOff(time.Second)))

	t.Logf("Waiting for upgrade watcher to finish...")
	err = upgradetest.WaitForNoWatcher(ctx, 2*time.Minute, 10*time.Second, 1*time.Minute+15*time.Second)
	if err != nil {
		return fmt.Errorf("waiting for upgrade watcher to finish: %w", err)
	}
	t.Logf("Upgrade watcher finished")

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = upgradetest.CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary)
	if err != nil {
		return fmt.Errorf("checking agent has not been rolled back: %w", err)
	}

	if upgradeOpts.PostWatcherSuccessHook != nil {
		err = upgradeOpts.PostWatcherSuccessHook(ctx, startFixture)
		if err != nil {
			return fmt.Errorf("PostWatcherSuccessHook failed: %w", err)
		}
	}
	return nil
}

func defaultPolicy() kibana.AgentPolicy {
	policyUUID := uuid.Must(uuid.NewV4()).String()

	policy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	return policy
}

// simulateAirGapedEnvironment uses iptables to block outgoing packages to the
// IPs (v4 and v6) associated with host.
func simulateAirGapedEnvironment(t *testing.T, host string) {
	ips, err := net.LookupIP(host)
	require.NoErrorf(t, err, "could not get IPs for host %q", host)

	// iptables -A OUTPUT -j DROP -d IP
	t.Logf("found %v IPs for %q, blocking them...", ips, host)
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
		t.Logf("use \"%s -D %s\" to remove it", cmd, strings.Join(args[1:], " "))
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

func newArtifactsServer(ctx context.Context, t *testing.T, version string, packageFormat string) *httptest.Server {
	fileServerDir := t.TempDir()
	downloadAt := filepath.Join(fileServerDir, "downloads", "beats", "elastic-agent", "beats", "elastic-agent")
	err := os.MkdirAll(downloadAt, 0700)
	require.NoError(t, err, "could not create directory structure for file server")

	fetcher := atesting.ArtifactFetcher()
	fr, err := fetcher.Fetch(ctx, runtime.GOOS, runtime.GOARCH, version, packageFormat)
	require.NoErrorf(t, err, "could not prepare fetcher to download agent %s",
		version)
	err = fr.Fetch(ctx, t, downloadAt)
	require.NoError(t, err, "could not download agent %s", version)

	// it's useful for debugging
	dl, err := os.ReadDir(downloadAt)
	require.NoError(t, err)
	var files []string
	for _, d := range dl {
		files = append(files, d.Name())
	}
	fmt.Printf("ArtifactsServer root dir %q, served files %q\n",
		fileServerDir, files)

	fs := http.FileServer(http.Dir(fileServerDir))

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

func agentUpgradeDetailsString(a kibana.GetAgentResponse) string {
	if a.UpgradeDetails == nil {
		return "upgrade details is NIL"
	}

	return fmt.Sprintf("%#v", *a.UpgradeDetails)
}

// startHTTPSFileServer prepares and returns a started HTTPS file server serving
// files from rootDir and using cert as its TLS certificate.
func startHTTPSFileServer(t *testing.T, rootDir string, cert tls.Certificate) *httptest.Server {
	// it's useful for debugging
	dl, err := os.ReadDir(rootDir)
	require.NoError(t, err)
	var files []string
	for _, d := range dl {
		files = append(files, d.Name())
	}
	fmt.Printf("ArtifactsServer root dir %q, served files %q\n",
		rootDir, files)

	fs := http.FileServer(http.Dir(rootDir))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("[fileserver] %s - %s", r.Method, r.URL.Path)
		fs.ServeHTTP(w, r)
	}))

	server.Listener, err = net.Listen("tcp", "127.0.0.1:443")
	require.NoError(t, err, "could not create net listener for port 443")

	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Logf("file server running on %s", server.URL)

	return server
}

// prepareTLSCerts generates a CA and a child certificate for the given host and
// IPs.
func prepareTLSCerts(t *testing.T, host string, ips []net.IP) (certutil.Pair, certutil.Pair, tls.Certificate) {
	rootKey, rootCACert, rootPair, err := certutil.NewRootCA()
	require.NoError(t, err, "could not create root CA")

	_, childPair, err := certutil.GenerateChildCert(
		host,
		ips,
		rootKey,
		rootCACert)
	require.NoError(t, err, "could not create child cert")

	cert, err := tls.X509KeyPair(childPair.Cert, childPair.Key)
	require.NoError(t, err, "could not create tls.Certificates from child certificate")

	return rootPair, childPair, cert
}

// impersonateHost impersonates 'host' by adding an entry to /etc/hosts mapping
// 'ip' to 'host'.
// It registers a function with t.Cleanup to restore /etc/hosts to its original
// state.
func impersonateHost(t *testing.T, host string, ip string) {
	copyFile(t, "/etc/hosts", "/etc/hosts.old")

	entry := fmt.Sprintf("\n%s\t%s\n", ip, host)
	f, err := os.OpenFile("/etc/hosts", os.O_WRONLY|os.O_APPEND, 0o644)
	require.NoError(t, err, "could not open file for append")

	_, err = f.Write([]byte(entry))
	require.NoError(t, err, "could not write data to file")
	require.NoError(t, f.Close(), "could not close file")

	t.Cleanup(func() {
		err := os.Rename("/etc/hosts.old", "/etc/hosts")
		require.NoError(t, err, "could not restore /etc/hosts")
	})
}

func copyFile(t *testing.T, srcPath, dstPath string) {
	t.Logf("copyFile: src %q, dst %q", srcPath, dstPath)
	src, err := os.Open(srcPath)
	require.NoError(t, err, "Failed to open source file")
	defer src.Close()

	dst, err := os.Create(dstPath)
	require.NoError(t, err, "Failed to create destination file")
	defer dst.Close()

	_, err = io.Copy(dst, src)
	require.NoError(t, err, "Failed to copy file")

	err = dst.Sync()
	require.NoError(t, err, "Failed to sync dst file")
}

func isFIPSCapableVersion(ver *version.ParsedSemVer) bool {
	// The 8.19.x versions are FIPS-capable
	if ver.Major() == 8 && ver.Minor() == 19 {
		return true
	}

	// Versions prior to 8.19.0 are not FIPS-capable
	if ver.Less(*version.NewParsedSemVer(8, 19, 0, "", "")) {
		return false
	}

	// The 9.0.x versions are not FIPS-capable
	if ver.Major() == 9 && ver.Minor() == 0 {
		return false
	}

	// All versions starting with 9.1.0-SNAPSHOT are FIPS-capable
	return true
}

// TestFleetUpgradeCommandPRBuildWithSource tests upgrading an agent enrolled in fleet using the upgrade command with the --source-uri and --force args
func TestFleetUpgradeCommandToPRBuildWithSource(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})
	ctx := t.Context()

	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "could not create fixture for latest release")
	err = startFixture.Prepare(ctx)
	require.NoError(t, err, "could not prepare startFixture")

	endFixture, err := atesting.NewFixture(
		t,
		upgradetest.EnsureSnapshot(define.Version()),
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err, "failed to get fixture with PR build")
	err = endFixture.Prepare(ctx)
	require.NoError(t, err, "could not prepare endFixture")

	// Process start and end fixtures
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)
	startParsedVersion, err := version.ParseVersion(startVersionInfo.Binary.String())
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)

	// Download end artifacts
	// os.MkDirTemp is used here instead of t.TempDir as there were permission issues in the test if t.TempDir was used.
	sourcePath, err := os.MkdirTemp("", "agent-upgrade-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		if !t.Failed() {
			if err := os.RemoveAll(sourcePath); err != nil {
				t.Logf("Error removing path %q: %v", sourcePath, err)
			}
		} else {
			t.Logf("Temporary directory %q preserved for investigation/debugging.", sourcePath)
		}
	})
	// Use acl instead of os here so Windows permissions are set correctly
	err = acl.Chmod(sourcePath, os.ModePerm)
	require.NoError(t, err, "unable to set temp dir permissions")
	t.Logf("Using temp dir %q with %o", sourcePath, os.ModePerm)
	t.Logf("Downloading version %s to %s", endFixture.Version(), sourcePath)
	fetcher := atesting.ArtifactFetcher()
	fetchRes, err := fetcher.Fetch(ctx, runtime.GOOS, runtime.GOARCH, endFixture.Version(), endFixture.PackageFormat())
	require.NoError(t, err)
	err = fetchRes.Fetch(ctx, t, sourcePath)
	require.NoError(t, err)

	if startVersionInfo.Binary.String() == endVersionInfo.Binary.String() &&
		startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Build under test is the same as the build from the artifacts repository (version: %s) [commit: %s]",
			startVersionInfo.Binary.String(), startVersionInfo.Binary.Commit)
	}
	if startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("Target version has the same commit hash %q", endVersionInfo.Binary.Commit)
	}

	t.Log("Creating Agent policy...")
	kibClient := info.KibanaClient
	policyResp, err := kibClient.CreatePolicy(ctx, defaultPolicy())
	require.NoError(t, err)

	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	})
	require.NoError(t, err)

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(ctx, kibClient)
	require.NoError(t, err)

	err = upgradetest.ConfigureFastWatcher(ctx, startFixture)
	require.NoError(t, err, "unable to write fast watcher config")

	t.Log("Installing Elastic Agent...")
	installOpts := atesting.InstallOpts{
		Force: true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerURL,
			EnrollmentToken: enrollmentToken.APIKey,
		},
	}
	output, err := startFixture.Install(ctx, &installOpts)
	t.Logf("Install agent output:\n%s", string(output))
	require.NoError(t, err)

	t.Log("Waiting for Agent to be correct version and healthy...")
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	agentID, err := startFixture.AgentID(ctx)
	require.NoError(t, err)
	t.Logf("Agent ID: %q", agentID)

	t.Log("Waiting for enrolled Agent status to be online...")
	require.Eventually(t, func() bool {
		return check.FleetAgentStatus(ctx, t, kibClient, agentID, "online")()
	}, time.Minute*2, time.Second, "Agent did not come online")

	t.Logf("Upgrading from version \"%s-%s\" to version \"%s-%s\"...",
		startParsedVersion, startVersionInfo.Binary.Commit,
		endVersionInfo.Binary.String(), endVersionInfo.Binary.Commit)
	upgradeArgs := []string{"upgrade", endVersionInfo.Binary.String(), "--force", "--source-uri", "file://" + sourcePath}
	upgradeOutput, err := startFixture.Exec(ctx, upgradeArgs)
	require.NoErrorf(t, err, "Upgrade command failed, output:\n%s", string(upgradeOutput))

	t.Log("Ensure agent status reports upgrade_details")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := startFixture.ExecStatus(ctx)
		require.NoError(c, err)
		require.NotNil(c, status.UpgradeDetails, "Agent status does not contain upgrade_details.")
	}, time.Minute*5, time.Second, "Agent does not report upgrade_details.")

	t.Log("Waiting for upgrade watcher to start...")
	err = upgradetest.WaitForWatcher(ctx, 5*time.Minute, 10*time.Second)
	require.NoError(t, err)
	t.Log("Upgrade watcher started")

	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	t.Log("Waiting for upgraded Agent status to be online...")
	require.Eventually(t, func() bool {
		return check.FleetAgentStatus(ctx, t, kibClient, agentID, "online")()
	}, time.Minute*10, time.Second*10, "Agent did not come online")

	t.Log("Check agent version")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		ver, err := fleettools.GetAgentVersion(ctx, kibClient, agentID)
		require.NoError(c, err)
		require.Equal(c, endVersionInfo.Binary.Version, ver)
	}, time.Minute*5, time.Second)

	t.Log("Waiting for upgrade watcher to finish...")
	err = upgradetest.WaitForNoWatcher(ctx, 2*time.Minute, 10*time.Second, 1*time.Minute+15*time.Second)
	require.NoError(t, err)

	err = upgradetest.CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary)
	require.NoError(t, err, "Post watcher check has failed, agent may have rolled back")
}
