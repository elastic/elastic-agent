// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gopkg.in/yaml.v2"

	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
)

const fastWatcherCfg = `
agent.upgrade.watcher:
  grace_period: 1m
  error_check.interval: 15s
  crash_check.interval: 15s
`

func TestFleetManagedUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	// Get version of this Agent build and ensure that it has a `-SNAPSHOT` suffix. We
	// do this by first removing the `-SNAPSHOT` suffix if it exists, and then appending
	// it. We use the `-SNAPSHOT`-suffixed version because it is guaranteed to exist, even
	// for unreleased versions.
	currentVersion := define.Version()
	currentVersion = strings.TrimRight(currentVersion, "-SNAPSHOT") + "-SNAPSHOT"

	upgradeFromVersion := "8.8.1"
	upgradeToVersion := currentVersion

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", upgradeFromVersion, upgradeToVersion)

	agentFixture, err := atesting.NewFixture(
		t,
		upgradeFromVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing agent fixture")

	err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	kibClient := info.KibanaClient
	policyUUID := uuid.New().String()

	t.Log("Creating Agent policy...")
	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policy, err := kibClient.CreatePolicy(createPolicyReq)
	require.NoError(t, err)

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(createEnrollmentApiKeyReq)
	require.NoError(t, err)

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := tools.GetDefaultFleetServerURL(kibClient)
	require.NoError(t, err)

	t.Log("Enrolling Elastic Agent...")
	output, err := tools.InstallAgent(fleetServerURL, enrollmentToken.APIKey, agentFixture)
	if err != nil {
		t.Log(string(output))
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		assert.NoError(t, tools.UnEnrollAgent(info.KibanaClient))
	})

	t.Log(`Waiting for enrolled Agent status to be "online"...`)
	require.Eventually(t, tools.WaitForAgentStatus(t, kibClient, "online"), 2*time.Minute, 10*time.Second, "Agent status is not online")

	t.Logf("Upgrade Elastic Agent to version %s...", upgradeToVersion)
	err = tools.UpgradeAgent(kibClient, upgradeToVersion)
	require.NoError(t, err)

	t.Log(`Waiting for enrolled Agent status to be "online"...`)
	require.Eventually(t, tools.WaitForAgentStatus(t, kibClient, "online"), 3*time.Minute, 15*time.Second, "Agent status is not online")

	// Upgrade Watcher check disabled until
	// https://github.com/elastic/elastic-agent/issues/2977 is resolved.
	// checkUpgradeWatcherRan(t, s.agentFixture)

	t.Log("Getting Agent version...")
	newVersion, err := tools.GetAgentVersion(kibClient)
	require.NoError(t, err)

	// We remove the `-SNAPSHOT` suffix because, post-upgrade, the version reported
	// by the Agent will not contain this suffix, even if a `-SNAPSHOT`-suffixed
	// version was used as the target version for the upgrade.
	require.Equal(t, strings.TrimRight(upgradeToVersion, `-SNAPSHOT`), newVersion)
}

func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		// Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: true,
		Sudo:    true, // requires Agent installation
	})

	agentFixture, err := define.NewFixture(t, define.Version())

	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing agent fixture")

	err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	const minVersionString = "8.9.0-SNAPSHOT"
	minVersion, _ := version.ParseVersion(minVersionString)
	pv, err := version.ParseVersion(define.Version())
	if pv.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersionString)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	output, err := tools.InstallStandaloneAgent(agentFixture)
	t.Logf("Agent installation output: %q", string(output))
	require.NoError(t, err)

	c := agentFixture.Client()

	require.Eventually(t, func() bool {
		err := c.Connect(ctx)
		if err != nil {
			t.Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("agent state: %+v", state)
		return state.State == cproto.State_HEALTHY
	}, 2*time.Minute, 10*time.Second, "Agent never became healthy")

	aac := tools.NewArtifactAPIClient()
	vList, err := aac.GetVersions(ctx)
	require.NoError(t, err, "error retrieving versions from Artifact API")
	require.NotNil(t, vList)

	sortedParsedVersions := make(version.SortableParsedVersions, 0, len(vList.Versions))
	for _, v := range vList.Versions {
		pv, err := version.ParseVersion(v)
		require.NoErrorf(t, err, "invalid version retrieved from artifact API: %q", v)
		sortedParsedVersions = append(sortedParsedVersions, pv)
	}

	require.NotEmpty(t, sortedParsedVersions)

	// normally the output of the versions returned by artifact API is already sorted in ascending order,
	// if we want to sort in descending order we could use
	sort.Sort(sort.Reverse(sortedParsedVersions))

	var latestSnapshotVersion *version.ParsedSemVer
	// fetch the latest SNAPSHOT build
	for _, pv := range sortedParsedVersions {
		if pv.IsSnapshot() {
			latestSnapshotVersion = pv
			break
		}
	}

	require.NotNil(t, latestSnapshotVersion)

	// get all the builds of the snapshot version (need to pass x.y.z-SNAPSHOT format)
	builds, err := aac.GetBuildsForVersion(ctx, latestSnapshotVersion.VersionWithPrerelease())
	require.NoError(t, err)
	// TODO if we don't have at least 2 builds, select the next older snapshot build
	require.Greater(t, len(builds.Builds), 1)

	// take the penultimate build of the snapshot (the builds are ordered from most to least recent)
	upgradeVersionString := builds.Builds[1]

	t.Logf("Targeting build %q of version %q", upgradeVersionString, latestSnapshotVersion)

	buildDetails, err := aac.GetBuildDetails(ctx, latestSnapshotVersion.VersionWithPrerelease(), upgradeVersionString)
	require.NoErrorf(t, err, "error accessing build details for version %q and buildID %q", latestSnapshotVersion.Original(), upgradeVersionString)
	require.NotNil(t, buildDetails)
	agentProject, ok := buildDetails.Build.Projects["elastic-agent"]
	require.Truef(t, ok, "elastic agent project not found in version %q build %q", latestSnapshotVersion.Original(), upgradeVersionString)
	t.Logf("agent build details: %+v", agentProject)
	t.Logf("expected agent commit hash: %q", agentProject.CommitHash)
	expectedAgentHashAfterUpgrade := agentProject.CommitHash

	// Workaround until issue with Artifact API build commit hash are resolved
	actualAgentHashAfterUpgrade := extractCommitHashFromArtifact(t, ctx, latestSnapshotVersion, agentProject)
	require.NotEmpty(t, actualAgentHashAfterUpgrade)

	t.Logf("Artifact API hash: %q Actual package hash: %q", expectedAgentHashAfterUpgrade, actualAgentHashAfterUpgrade)

	// override the expected hash with the one extracted from the actual artifact
	expectedAgentHashAfterUpgrade = actualAgentHashAfterUpgrade

	buildFragments := strings.Split(upgradeVersionString, "-")
	require.Lenf(t, buildFragments, 2, "version %q returned by artifact api is not in format <version>-<buildID>", upgradeVersionString)

	upgradeInputVersion := version.NewParsedSemVer(
		latestSnapshotVersion.Major(),
		latestSnapshotVersion.Minor(),
		latestSnapshotVersion.Patch(),
		latestSnapshotVersion.Prerelease(),
		buildFragments[1],
	)

	t.Logf("Upgrading to version %q", upgradeInputVersion)

	err = c.Connect(ctx)
	require.NoError(t, err, "error connecting client to agent")
	defer c.Disconnect()

	_, err = c.Upgrade(ctx, upgradeInputVersion.String(), "", false)
	require.NoErrorf(t, err, "error triggering agent upgrade to version %q", upgradeInputVersion.String())

	require.Eventuallyf(t, func() bool {
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("current agent state: %+v", state)
		return state.Info.Commit == expectedAgentHashAfterUpgrade && state.State == cproto.State_HEALTHY
	}, 5*time.Minute, 1*time.Second, "agent never upgraded to expected version")

	checkUpgradeWatcherRan(t, agentFixture)

	version, err := c.Version(ctx)
	require.NoError(t, err, "error checking version after upgrade")
	require.Equal(t, expectedAgentHashAfterUpgrade, version.Commit, "agent commit hash changed after upgrade")
}

// checkUpgradeWatcherRan asserts that the Upgrade Watcher finished running. We use the
// presence of the update marker file as evidence that the Upgrade Watcher is still running
// and the absence of that file as evidence that the Upgrade Watcher is no longer running.
func checkUpgradeWatcherRan(t *testing.T, agentFixture *atesting.Fixture) {
	t.Helper()
	t.Log("Waiting for upgrade watcher to finish running...")

	updateMarkerFile := filepath.Join(agentFixture.WorkDir(), "data", ".update-marker")
	require.FileExists(t, updateMarkerFile)

	now := time.Now()
	require.Eventuallyf(t, func() bool {
		_, err := os.Stat(updateMarkerFile)
		return errors.Is(err, fs.ErrNotExist)
	}, 2*time.Minute, 15*time.Second, "agent never removed update marker")
	t.Logf("Upgrade Watcher completed in %s", time.Now().Sub(now))
}

func extractCommitHashFromArtifact(t *testing.T, ctx context.Context, artifactVersion *version.ParsedSemVer, agentProject tools.Project) string {
	tmpDownloadDir := t.TempDir()

	operatingSystem := runtime.GOOS
	architecture := runtime.GOARCH
	suffix, err := atesting.GetPackageSuffix(operatingSystem, architecture)
	require.NoErrorf(t, err, "error determining suffix for OS %q and arch %q", operatingSystem, architecture)
	prefix := fmt.Sprintf("elastic-agent-%s", artifactVersion.VersionWithPrerelease())
	pkgName := fmt.Sprintf("%s-%s", prefix, suffix)
	require.Containsf(t, agentProject.Packages, pkgName, "Artifact API response does not contain pkg %s", pkgName)
	artifactFilePath := filepath.Join(tmpDownloadDir, pkgName)
	err = atesting.DownloadPackage(ctx, t, http.DefaultClient, agentProject.Packages[pkgName].URL, artifactFilePath)
	require.NoError(t, err, "error downloading package")
	err = atesting.ExtractArtifact(t, artifactFilePath, tmpDownloadDir)
	require.NoError(t, err, "error extracting artifact")

	matches, err := filepath.Glob(filepath.Join(tmpDownloadDir, "elastic-agent-*", ".build_hash.txt"))
	require.NoError(t, err)
	require.NotEmpty(t, matches)

	hashFilePath := matches[0]
	t.Logf("Accessing hash file %q", hashFilePath)
	hashBytes, err := os.ReadFile(hashFilePath)
	require.NoError(t, err, "error reading build hash")
	return strings.TrimSpace(string(hashBytes))
}

type versionInfo struct {
	Version string `yaml:"version"`
	Commit  string `yaml:"commit"`
}

type versionOutput struct {
	Binary versionInfo `yaml:"binary"`
	Daemon versionInfo `yaml:"daemon"`
}

func TestStandaloneUpgradeRetryDownload(t *testing.T) {
	define.Require(t, define.Requirements{
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation and modifying /etc/hosts
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		}, // modifying /etc/hosts
	})

	upgradeFromVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	// We go back TWO minors because sometimes we are in a situation where
	// the current version has been advanced to the next release (e.g. 8.10.0)
	// but the version before that (e.g. 8.9.0) hasn't been released yet.
	previousVersion, err := upgradeFromVersion.GetPreviousMinor()
	require.NoError(t, err)
	previousVersion, err = previousVersion.GetPreviousMinor()
	require.NoError(t, err)

	// For testing the upgrade we actually perform a downgrade
	upgradeToVersion := previousVersion

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", upgradeFromVersion, upgradeToVersion)

	agentFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing agent fixture")

	err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	t.Log("Install the built Agent")
	output, err := tools.InstallStandaloneAgent(agentFixture)
	t.Log(string(output))
	require.NoError(t, err)

	t.Log("Ensure the correct version is running")
	currentVersion, err := getVersion(t, ctx, agentFixture)
	require.NoError(t, err)

	t.Log("Modify /etc/hosts to simulate transient network error")
	cmd := exec.Command("sed",
		"-i.bak",
		"s/localhost/localhost artifacts.elastic.co artifacts-api.elastic.co/g",
		"/etc/hosts",
	)
	t.Log("/etc/hosts modify command: ", cmd.String())

	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Log(string(output))
	}
	require.NoError(t, err)

	// Ensure that /etc/hosts is modified
	require.Eventually(t, func() bool {
		cmd := exec.Command("grep",
			"artifacts",
			"/etc/hosts",
		)
		t.Log("Check /etc/hosts command: ", cmd.String())

		// We don't check the error as grep will return non-zero exit code when
		// it doesn't find any matches, which could happen the first couple of
		// times it searches /etc/hosts.
		output, _ := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		return outputStr != ""
	}, 10*time.Second, 1*time.Second)

	defer restoreEtcHosts()

	t.Log("Start the Agent upgrade")
	var toVersion = upgradeToVersion.String()
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)

		err := upgradeAgent(ctx, toVersion, agentFixture, t.Log)

		wg.Done()
		require.NoError(t, err)
	}()

	t.Log("Check Agent logs for at least two retry messages")
	agentDirName := fmt.Sprintf("elastic-agent-%s", release.TrimCommit(currentVersion.Daemon.Commit))
	logsPath := filepath.Join(paths.DefaultBasePath, "Elastic", "Agent", "data", agentDirName, "logs")
	require.Eventually(t, func() bool {
		cmd := exec.Command("grep",
			"download.*retrying",
			"--recursive",
			"--include", "*.ndjson",
			logsPath,
		)
		t.Log("Find logs command: ", cmd.String())

		// We don't check the error as grep will return non-zero exit code when
		// it doesn't find any matches, which could happen the first couple of
		// times it searches the Elastic Agent logs.
		output, _ := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		outputLines := strings.Split(outputStr, "\n")
		t.Log(outputLines)
		t.Log("Number of retry messages: ", len(outputLines))
		return len(outputLines) >= 2
	}, 2*time.Minute, 20*time.Second)

	t.Log("Restore /etc/hosts so upgrade can proceed")
	err = restoreEtcHosts()
	require.NoError(t, err)

	// Wait for upgrade command to finish executing
	t.Log("Waiting for upgrade to finish")
	wg.Wait()

	checkUpgradeWatcherRan(t, agentFixture)

	t.Log("Check Agent version to ensure upgrade is successful")
	currentVersion, err = getVersion(t, ctx, agentFixture)
	require.NoError(t, err)
	require.Equal(t, toVersion, currentVersion.Binary.Version)
	require.Equal(t, toVersion, currentVersion.Daemon.Version)
}

func getVersion(t *testing.T, ctx context.Context, agentFixture *atesting.Fixture) (*versionOutput, error) {
	var currentVersion versionOutput
	var err error

	require.Eventually(t, func() bool {
		args := []string{"version", "--yaml"}
		var output []byte
		output, err = agentFixture.Exec(ctx, args)
		if err != nil {
			t.Log(string(output))
			return false
		}

		err = yaml.Unmarshal(output, &currentVersion)
		return err == nil
	}, 1*time.Minute, 1*time.Second)

	return &currentVersion, err
}

func restoreEtcHosts() error {
	cmd := exec.Command("mv",
		"/etc/hosts.bak",
		"/etc/hosts",
	)
	return cmd.Run()
}

func upgradeAgent(ctx context.Context, version string, agentFixture *atesting.Fixture, log func(args ...any)) error {
	args := []string{"upgrade", version}
	output, err := agentFixture.Exec(ctx, args)
	if err != nil {
		log("Upgrade command output after error: ", string(output))
		return err
	}

	return nil
}
