// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"encoding/json"
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

	"gopkg.in/yaml.v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	cmdVersion "github.com/elastic/elastic-agent/internal/pkg/basecmd/version"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	v1client "github.com/elastic/elastic-agent/pkg/control/v1/client"
	v2client "github.com/elastic/elastic-agent/pkg/control/v2/client"
	v2proto "github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
	agtversion "github.com/elastic/elastic-agent/version"
)

const fastWatcherCfg = `
agent.upgrade.watcher:
  grace_period: 1m
  error_check.interval: 15s
  crash_check.interval: 15s
`

// notable versions used in tests

// first version to include --non-interactive flag during install
var version_8_2_0 = version.NewParsedSemVer(8, 2, 0, "", "")

// first version to use agent v2 protocol
var version_8_6_0 = version.NewParsedSemVer(8, 6, 0, "", "")

// minimum version for passing --skip-verify when upgrading
var version_8_7_0 = version.NewParsedSemVer(8, 7, 0, "", "")

// minimum version for upgrade to specific snapshot + minimum version for setting shorter watch period after upgrade
var version_8_9_0_SNAPSHOT = version.NewParsedSemVer(8, 9, 0, "SNAPSHOT", "")

// minimum version for upgrade with remote pgp and skipping default pgp verification
var version_8_10_0_SNAPSHOT = version.NewParsedSemVer(8, 10, 0, "SNAPSHOT", "")

func TestFleetManagedUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	upgradableVersions := getUpgradableVersions(ctx, t, define.Version())

	for _, parsedVersion := range upgradableVersions {

		t.Run(fmt.Sprintf("Upgrade managed agent from %s to %s", parsedVersion, define.Version()), func(t *testing.T) {
			agentFixture, err := atesting.NewFixture(
				t,
				parsedVersion.String(),
				atesting.WithFetcher(atesting.ArtifactFetcher()),
			)
			require.NoError(t, err)
			err = agentFixture.Prepare(ctx)
			require.NoError(t, err, "error preparing agent fixture")

			err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
			require.NoError(t, err, "error configuring agent fixture")
			testUpgradeFleetManagedElasticAgent(t, ctx, info, agentFixture, parsedVersion, define.Version())
		})
	}
}

func testUpgradeFleetManagedElasticAgent(t *testing.T, ctx context.Context, info *define.Info, agentFixture *atesting.Fixture, parsedFromVersion *version.ParsedSemVer, toVersion string) {
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
	policy, err := kibClient.CreatePolicy(ctx, createPolicyReq)
	require.NoError(t, err)

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentApiKeyReq)
	require.NoError(t, err)

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := tools.GetDefaultFleetServerURL(kibClient)
	require.NoError(t, err)

	t.Log("Enrolling Elastic Agent...")
	var nonInteractiveFlag bool
	if version_8_2_0.Less(*parsedFromVersion) {
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
	output, err := tools.InstallAgent(installOpts, agentFixture)
	if err != nil {
		t.Log(string(output))
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		t.Log("Un-enrolling Elastic Agent...")
		assert.NoError(t, tools.UnEnrollAgent(info.KibanaClient, policy.ID))
	})

	t.Log(`Waiting for enrolled Agent status to be "online"...`)
	require.Eventually(t, tools.WaitForAgentStatus(t, kibClient, policy.ID, "online"), 2*time.Minute, 10*time.Second, "Agent status is not online")

	t.Logf("Upgrade Elastic Agent to version %s...", toVersion)
	err = tools.UpgradeAgent(kibClient, policy.ID, toVersion)
	require.NoError(t, err)

	t.Log(`Waiting for enrolled Agent status to be "online"...`)
	require.Eventually(t, tools.WaitForAgentStatus(t, kibClient, policy.ID, "online"), 10*time.Minute, 15*time.Second, "Agent status is not online")

	// We remove the `-SNAPSHOT` suffix because, post-upgrade, the version reported
	// by the Agent will not contain this suffix, even if a `-SNAPSHOT`-suffixed
	// version was used as the target version for the upgrade.
	require.Eventually(t, func() bool {
		t.Log("Getting Agent version...")
		newVersion, err := tools.GetAgentVersion(kibClient, policy.ID)
		if err != nil {
			t.Logf("error getting agent version: %v", err)
			return false
		}
		return strings.TrimRight(toVersion, `-SNAPSHOT`) == newVersion
	}, 5*time.Minute, time.Second)
}

func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		Local:   false, // requires Agent installation
		Isolate: true,
		Sudo:    true, // requires Agent installation
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	versionList := getUpgradableVersions(ctx, t, define.Version())

	for _, parsedVersion := range versionList {

		t.Run(fmt.Sprintf("Upgrade %s to %s", parsedVersion, define.Version()), func(t *testing.T) {
			agentFixture, err := atesting.NewFixture(
				t,
				parsedVersion.String(),
				atesting.WithFetcher(atesting.ArtifactFetcher()),
			)

			require.NoError(t, err, "error creating fixture")

			err = agentFixture.Prepare(ctx)
			require.NoError(t, err, "error preparing agent fixture")

			err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
			require.NoError(t, err, "error configuring agent fixture")

			parsedUpgradeVersion, err := version.ParseVersion(define.Version())
			require.NoErrorf(t, err, "define.Version() %q cannot be parsed as agent version", define.Version())
			skipVerify := version_8_7_0.Less(*parsedVersion)
			testStandaloneUpgrade(ctx, t, agentFixture, parsedVersion, parsedUpgradeVersion, "", skipVerify, true, false, CustomPGP{})
		})
	}
}

func TestStandaloneUpgradeWithGPGFallback(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := version_8_10_0_SNAPSHOT
	fromVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if fromVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// previous
	toVersion, err := fromVersion.GetPreviousMinor()
	require.NoError(t, err, "failed to get previous minor")
	agentFixture, err := define.NewFixture(
		t,
		define.Version(),
	)
	require.NoError(t, err, "error creating fixture")

	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing agent fixture")

	err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	_, defaultPGP := release.PGP()
	firstSeven := string(defaultPGP[:7])
	newPgp := strings.Replace(
		string(defaultPGP),
		firstSeven,
		"abcDEFg",
		1,
	)

	customPGP := CustomPGP{
		PGP: newPgp,
	}

	testStandaloneUpgrade(ctx, t, agentFixture, fromVersion, toVersion, "", false, false, true, customPGP)
}

func TestStandaloneUpgradeWithGPGFallbackOneRemoteFailing(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := version_8_10_0_SNAPSHOT
	fromVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if fromVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// previous
	toVersion, err := fromVersion.GetPreviousMinor()
	require.NoError(t, err, "failed to get previous minor")
	agentFixture, err := define.NewFixture(
		t,
		define.Version(),
	)
	require.NoError(t, err, "error creating fixture")

	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing agent fixture")

	err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	_, defaultPGP := release.PGP()
	firstSeven := string(defaultPGP[:7])
	newPgp := strings.Replace(
		string(defaultPGP),
		firstSeven,
		"abcDEFg",
		1,
	)

	customPGP := CustomPGP{
		PGP:    newPgp,
		PGPUri: "https://127.0.0.1:3456/non/existing/path",
	}

	testStandaloneUpgrade(ctx, t, agentFixture, fromVersion, toVersion, "", false, false, true, customPGP)
}

func TestStandaloneDowngradeToPreviousSnapshotBuild(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	minVersion := version_8_9_0_SNAPSHOT
	pv, err := version.ParseVersion(define.Version())
	if pv.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	agentFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing agent fixture")

	err = agentFixture.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	// retrieve all the versions of agent from the artifact API
	aac := tools.NewArtifactAPIClient()
	latestSnapshotVersion, err := tools.GetLatestSnapshotVersion(ctx, t, aac)
	require.NoError(t, err)

	// get all the builds of the snapshot version (need to pass x.y.z-SNAPSHOT format)
	builds, err := aac.GetBuildsForVersion(ctx, latestSnapshotVersion.VersionWithPrerelease())
	require.NoError(t, err)

	if len(builds.Builds) < 2 {
		t.Skip("there is only one SNAPSHOT version available, " +
			"the test requires at least 2 so it can downgrade to the previous" +
			"SNAPSHOT")
	}
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

	t.Logf("Targeting upgrade to version %+v", upgradeInputVersion)
	parsedFromVersion, err := version.ParseVersion(define.Version())
	require.NoErrorf(t, err, "define.Version() %q cannot be parsed as agent version", define.Version())
	testStandaloneUpgrade(ctx, t, agentFixture, parsedFromVersion, upgradeInputVersion, expectedAgentHashAfterUpgrade, false, true, false, CustomPGP{})
}

func getUpgradableVersions(ctx context.Context, t *testing.T, upgradeToVersion string) (upgradableVersions []*version.ParsedSemVer) {
	t.Helper()

	const currentMajorVersions = 2
	const previousMajorVersions = 1

	aac := tools.NewArtifactAPIClient()
	vList, err := aac.GetVersions(ctx)
	require.NoError(t, err, "error retrieving versions from Artifact API")
	require.NotEmpty(t, vList)

	parsedUpgradeToVersion, err := version.ParseVersion(upgradeToVersion)
	require.NoErrorf(t, err, "upgradeToVersion %q is not a valid version string", upgradeToVersion)
	currentMajor := parsedUpgradeToVersion.Major()
	var currentMajorSelected, previousMajorSelected int

	sortedParsedVersions := make(version.SortableParsedVersions, 0, len(vList.Versions))
	for _, v := range vList.Versions {
		pv, err := version.ParseVersion(v)
		require.NoErrorf(t, err, "invalid version retrieved from artifact API: %q", v)
		sortedParsedVersions = append(sortedParsedVersions, pv)
	}

	require.NotEmpty(t, sortedParsedVersions)

	// normally the output of the versions returned by artifact API is already sorted in ascending order,
	// we want to sort in descending orders, so we sort them
	sort.Sort(sort.Reverse(sortedParsedVersions))

	for _, parsedVersion := range sortedParsedVersions {
		if currentMajorSelected == currentMajorVersions && previousMajorSelected == previousMajorVersions {
			// we got all the versions we need, break the loop
			break
		}

		if !parsedVersion.Less(*parsedUpgradeToVersion) {
			// skip upgrade from newer versions than the one under test
			t.Logf("Skipping version %q since it's newer or equal to version after upgrade %q", parsedVersion, parsedUpgradeToVersion)
			continue
		}

		if parsedVersion.IsSnapshot() {
			// skip all snapshots
			continue
		}

		if parsedVersion.Major() == currentMajor && currentMajorSelected < currentMajorVersions {
			upgradableVersions = append(upgradableVersions, parsedVersion)
			currentMajorSelected++
			continue
		}

		if parsedVersion.Major() < currentMajor && previousMajorSelected < previousMajorVersions {
			upgradableVersions = append(upgradableVersions, parsedVersion)
			previousMajorSelected++
			continue
		}

	}
	return
}

func testStandaloneUpgrade(
	ctx context.Context,
	t *testing.T,
	f *atesting.Fixture,
	parsedFromVersion *version.ParsedSemVer,
	parsedUpgradeVersion *version.ParsedSemVer,
	expectedAgentHashAfterUpgrade string,
	allowLocalPackage bool,
	skipVerify bool,
	skipDefaultPgp bool,
	customPgp CustomPGP,
) {

	var nonInteractiveFlag bool
	if version_8_2_0.Less(*parsedFromVersion) {
		nonInteractiveFlag = true
	}
	installOpts := atesting.InstallOpts{
		NonInteractive: nonInteractiveFlag,
		Force:          true,
	}

	output, err := tools.InstallAgent(installOpts, f)
	t.Logf("Agent installation output: %q", string(output))
	require.NoError(t, err)

	c := f.Client()

	err = c.Connect(ctx)
	require.NoError(t, err, "error connecting client to agent")
	defer c.Disconnect()

	require.Eventually(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, f, parsedFromVersion.CoreVersion(), parsedFromVersion.IsSnapshot(), "")
	}, 2*time.Minute, 10*time.Second, "Agent never became healthy")

	t.Logf("Upgrading from version %q to version %q", parsedFromVersion, parsedUpgradeVersion)

	upgradeCmdArgs := []string{"upgrade", parsedUpgradeVersion.String()}

	useLocalPackage := allowLocalPackage && version_8_7_0.Less(*parsedFromVersion)
	if useLocalPackage {
		// if we are upgrading from a version > 8.7.0 (min version to skip signature verification) we pass :
		// - a file:// sourceURI pointing the agent package under test
		// - flag --skip-verify to bypass pgp signature verification (we don't produce signatures for PR/main builds)
		tof, err := define.NewFixture(t, parsedUpgradeVersion.String())
		require.NoError(t, err)

		srcPkg, err := tof.SrcPackage(ctx)
		require.NoError(t, err)
		sourceURI := "file://" + filepath.Dir(srcPkg)
		t.Logf("setting sourceURI to : %q", sourceURI)
		upgradeCmdArgs = append(upgradeCmdArgs, "--source-uri", sourceURI)
	}
	if useLocalPackage || skipVerify {
		upgradeCmdArgs = append(upgradeCmdArgs, "--skip-verify")
	}

	if skipDefaultPgp {
		upgradeCmdArgs = append(upgradeCmdArgs, "--skip-default-pgp")
	}

	if len(customPgp.PGP) > 0 {
		upgradeCmdArgs = append(upgradeCmdArgs, "--pgp", customPgp.PGP)
	}

	if len(customPgp.PGPUri) > 0 {
		upgradeCmdArgs = append(upgradeCmdArgs, "--pgp-uri", customPgp.PGPUri)
	}

	if len(customPgp.PGPPath) > 0 {
		upgradeCmdArgs = append(upgradeCmdArgs, "--pgp-path", customPgp.PGPPath)
	}

	upgradeTriggerOutput, err := f.Exec(ctx, upgradeCmdArgs)
	require.NoErrorf(t, err, "error triggering agent upgrade to version %q, output:\n%s",
		parsedUpgradeVersion, upgradeTriggerOutput)

	require.Eventuallyf(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, f, parsedUpgradeVersion.CoreVersion(), parsedUpgradeVersion.IsSnapshot(), expectedAgentHashAfterUpgrade)
	}, 5*time.Minute, 1*time.Second, "agent never upgraded to expected version")

	checkUpgradeWatcherRan(t, f, parsedFromVersion)

	if expectedAgentHashAfterUpgrade != "" {
		aVersion, err := c.Version(ctx)
		assert.NoError(t, err, "error checking version after upgrade")
		assert.Equal(t, expectedAgentHashAfterUpgrade, aVersion.Commit, "agent commit hash changed after upgrade")
	}
}

func checkAgentHealthAndVersion(t *testing.T, ctx context.Context, f *atesting.Fixture, expectedVersion string, snapshot bool, expectedHash string) bool {
	t.Helper()

	parsedExpectedVersion, err := version.ParseVersion(expectedVersion)
	require.NoErrorf(t, err, "Expected version %q is not parseable", expectedVersion)

	if parsedExpectedVersion.Less(*version_8_6_0) {
		// we have to parse v1 state response
		return checkLegacyAgentHealthAndVersion(t, ctx, f, expectedVersion, snapshot, expectedHash)
	}

	stateOut, err := f.Exec(ctx, []string{"status", "--output", "yaml"})
	if err != nil {
		t.Logf("error getting the agent state: %v", err)
		return false
	}

	var state v2client.AgentState
	err = yaml.Unmarshal(stateOut, &state)
	if err != nil {
		t.Logf("error unmarshaling the agent state: %v", err)
		return false
	}

	t.Logf("current agent state: %+v", state)
	info := state.Info
	if expectedHash != "" {
		return info.Commit == expectedHash && state.State == v2proto.State_HEALTHY
	}
	return info.Version == expectedVersion &&
		info.Snapshot == snapshot &&
		state.State == v2proto.State_HEALTHY
}

func checkLegacyAgentHealthAndVersion(t *testing.T, ctx context.Context, f *atesting.Fixture, expectedVersion string, snapshot bool, expectedHash string) bool {
	stateOut, err := f.Exec(ctx, []string{"status", "--output", "json"})
	if err != nil {
		t.Logf("error getting the agent state: %v", err)
		return false
	}

	var state v1client.AgentStatus
	err = json.Unmarshal(stateOut, &state)
	if err != nil {
		t.Logf("error unmarshaling the agent state: %v", err)
		return false
	}

	t.Logf("current agent state: %+v", state)

	versionOut, err := f.Exec(ctx, []string{"version", "--yaml"})
	if err != nil {
		t.Logf("error getting the agent version: %v", err)
		return false
	}
	var aVersion cmdVersion.Output
	err = yaml.Unmarshal(versionOut, &aVersion)
	if err != nil {
		t.Logf("error unmarshaling version output: %v", err)
		return false
	}
	t.Logf("current agent version: %+v", aVersion)
	if expectedHash != "" {
		return aVersion.Daemon.Commit == expectedHash && state.Status == v1client.Healthy
	}
	return aVersion.Daemon.Version == expectedVersion &&
		aVersion.Daemon.Snapshot == snapshot && state.Status == v1client.Healthy

}

// checkUpgradeWatcherRan asserts that the Upgrade Watcher finished running. We use the
// presence of the update marker file as evidence that the Upgrade Watcher is still running
// and the absence of that file as evidence that the Upgrade Watcher is no longer running.
func checkUpgradeWatcherRan(t *testing.T, agentFixture *atesting.Fixture, fromVersion *version.ParsedSemVer) {
	t.Helper()

	if fromVersion.Less(*version_8_9_0_SNAPSHOT) {
		t.Logf("Version %q is too old for a quick update marker check, skipping...", fromVersion)
		return
	}

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

	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/3155")

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
	toVersion := upgradeToVersion.String()
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

	checkUpgradeWatcherRan(t, agentFixture, upgradeFromVersion)

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

func TestUpgradeBrokenPackageVersion(t *testing.T) {
	define.Require(t, define.Requirements{
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	f, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = f.Prepare(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = f.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	output, err := tools.InstallStandaloneAgent(f)
	t.Logf("Agent installation output: %q", string(output))
	require.NoError(t, err)

	c := f.Client()

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
		return state.State == v2proto.State_HEALTHY
	}, 2*time.Minute, 10*time.Second, "Agent never became healthy")

	// get rid of the package version files in the installed directory
	removePackageVersionFiles(t, f)

	// get the version returned by the currently running agent
	actualVersionBytes := getAgentVersion(t, f, context.Background(), false)

	actualVersion := unmarshalVersionOutput(t, actualVersionBytes, "daemon")

	// start the upgrade to the latest version
	require.NotEmpty(t, actualVersion, "broken agent package version should not be empty")

	// upgrade to latest version whatever that will be
	aac := tools.NewArtifactAPIClient()
	versionList, err := aac.GetVersions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, versionList.Versions, "Artifact API returned no versions")
	latestVersion := versionList.Versions[len(versionList.Versions)-1]

	t.Logf("Upgrading to version %q", latestVersion)

	err = c.Connect(ctx)
	require.NoError(t, err, "error connecting client to agent")
	defer c.Disconnect()

	_, err = c.Upgrade(ctx, latestVersion, "", false, false)
	require.NoErrorf(t, err, "error triggering agent upgrade to version %q", latestVersion)
	parsedLatestVersion, err := version.ParseVersion(latestVersion)
	require.NoError(t, err)

	require.Eventuallyf(t, func() bool {
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("current agent state: %+v", state)
		return state.Info.Version == parsedLatestVersion.CoreVersion() &&
			state.Info.Snapshot == parsedLatestVersion.IsSnapshot() &&
			state.State == v2proto.State_HEALTHY
	}, 5*time.Minute, 10*time.Second, "agent never upgraded to expected version")
}

func removePackageVersionFiles(t *testing.T, f *atesting.Fixture) {
	installFS := os.DirFS(f.WorkDir())
	matches := []string{}

	err := fs.WalkDir(installFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Name() == agtversion.PackageVersionFileName {
			matches = append(matches, path)
		}
		return nil
	})
	require.NoError(t, err)

	t.Logf("package version files found: %v", matches)

	// the version files should have been removed from the other test, we just make sure
	for _, m := range matches {
		vFile := filepath.Join(f.WorkDir(), m)
		t.Logf("removing package version file %q", vFile)
		err = os.Remove(vFile)
		require.NoErrorf(t, err, "error removing package version file %q", vFile)
	}
}

// TestStandaloneUpgradeFailsStatus tests the scenario where upgrading to a new version
// of Agent fails due to the new Agent binary reporting an unhealthy status. It checks
// that the Agent is rolled back to the previous version.
func TestStandaloneUpgradeFailsStatus(t *testing.T) {
	define.Require(t, define.Requirements{
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	t.Skip("Affected by https://github.com/elastic/elastic-agent/issues/3371, watcher left running at end of test")

	upgradeFromVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get available versions from Artifacts API
	aac := tools.NewArtifactAPIClient()
	versionList, err := aac.GetVersions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, versionList.Versions, "Artifact API returned no versions")

	// Determine the version that's TWO versions behind the latest. This is necessary for two reasons:
	// 1. We don't want to necessarily use the latest version as it might be the same as the
	// local one, which will then cause the invalid input in the Agent test policy (defined further
	// below in this test) to come into play with the Agent version we're upgrading from, thus preventing
	// it from ever becoming healthy.
	// 2. We don't want to necessarily use the version that's one before the latest because sometimes we
	// are in a situation where the latest version has been advanced to the next release (e.g. 8.10.0)
	// but the version before that (e.g. 8.9.0) hasn't been released yet.
	require.GreaterOrEqual(t, len(versionList.Versions), 3)
	upgradeToVersionStr := versionList.Versions[len(versionList.Versions)-3]

	upgradeToVersion, err := version.ParseVersion(upgradeToVersionStr)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", upgradeFromVersion, upgradeToVersion)

	agentFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing agent fixture")

	// Configure Agent with fast watcher configuration and also an invalid
	// input when the Agent version matches the upgraded Agent version. This way
	// the pre-upgrade version of the Agent runs healthy, but the post-upgrade
	// version doesn't.
	invalidInputPolicy := fastWatcherCfg + fmt.Sprintf(`
outputs:
  default:
    type: elasticsearch
    hosts: [127.0.0.1:9200]

inputs:
  - condition: '${agent.version.version} == "%s"'
    type: invalid
    id: invalid-input
`, upgradeToVersion.CoreVersion())

	err = agentFixture.Configure(ctx, []byte(invalidInputPolicy))
	require.NoError(t, err, "error configuring agent fixture")

	t.Log("Install the built Agent")
	output, err := tools.InstallStandaloneAgent(agentFixture)
	t.Log(string(output))
	require.NoError(t, err)

	c := agentFixture.Client()
	require.Eventually(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, agentFixture, upgradeFromVersion.CoreVersion(), upgradeFromVersion.IsSnapshot(), "")
	}, 2*time.Minute, 10*time.Second, "Agent never became healthy")

	toVersion := upgradeToVersion.String()
	t.Logf("Upgrading Agent to %s", toVersion)
	err = c.Connect(ctx)
	require.NoError(t, err, "error connecting client to agent")
	defer c.Disconnect()

	_, err = c.Upgrade(ctx, toVersion, "", false, false)
	require.NoErrorf(t, err, "error triggering agent upgrade to version %q", toVersion)

	require.Eventually(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, agentFixture, upgradeToVersion.CoreVersion(), upgradeToVersion.IsSnapshot(), "")
	}, 2*time.Minute, 250*time.Millisecond, "Upgraded Agent never became healthy")

	t.Log("Ensure the we have rolled back and the correct version is running")
	require.Eventually(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, agentFixture, upgradeFromVersion.CoreVersion(), upgradeFromVersion.IsSnapshot(), "")
	}, 2*time.Minute, 10*time.Second, "Rolled back Agent never became healthy")
}

type CustomPGP struct {
	PGP     string
	PGPUri  string
	PGPPath string
}

// TestStandaloneUpgradeFailsRestart tests the scenario where upgrading to a new version
// of Agent fails due to the new Agent binary not starting up. It checks that the Agent is
// rolled back to the previous version.
func TestStandaloneUpgradeFailsRestart(t *testing.T) {
	define.Require(t, define.Requirements{
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	toVersion := define.Version()
	toVersionParsed, err := version.ParseVersion(toVersion)
	require.NoError(t, err)

	// For the fromVersion, we go back TWO minors because sometimes we are in a
	// situation where the current version has been advanced to the next
	// release (e.g. 8.10.0) but the version before that (e.g. 8.9.0) hasn't been
	// released yet.
	fromVersionParsed, err := toVersionParsed.GetPreviousMinor()
	require.NoError(t, err)
	fromVersionParsed, err = fromVersionParsed.GetPreviousMinor()
	require.NoError(t, err)

	// Drop the SNAPSHOT and metadata as we may have stopped publishing snapshots
	// for versions that are two minors old.
	fromVersion := fromVersionParsed.CoreVersion()

	t.Logf("Upgrading Elastic Agent from %s to %s", fromVersion, toVersion)

	// Get path to Elastic Agent executable
	fromF, err := atesting.NewFixture(t, fromVersion)
	require.NoError(t, err)

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fromF.Prepare(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err = fromF.Configure(ctx, []byte(fastWatcherCfg))
	require.NoError(t, err, "error configuring agent fixture")

	output, err := tools.InstallStandaloneAgent(fromF)
	t.Logf("Agent installation output: %q", string(output))
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, fromF, fromVersion, false, "")
	}, 2*time.Minute, 10*time.Second, "Installed Agent never became healthy")

	t.Logf("Attempting upgrade to %s", toVersion)
	toF, err := define.NewFixture(t, toVersion)
	require.NoError(t, err)

	packagePath, err := toF.SrcPackage(ctx)
	require.NoError(t, err)

	upgradeCmdArgs := []string{
		"upgrade", toVersion,
		"--source-uri", "file://" + filepath.Dir(packagePath),
		"--skip-verify",
	}

	upgradeTriggerOutput, err := fromF.Exec(ctx, upgradeCmdArgs)
	require.NoErrorf(t, err, "error triggering agent upgrade to version %q, output:\n%s",
		toVersion, upgradeTriggerOutput)

	// Ensure new (post-upgrade) version is running and Agent is healthy
	require.Eventually(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, fromF, toVersionParsed.CoreVersion(), toVersionParsed.IsSnapshot(), "")
	}, 2*time.Minute, 10*time.Second, "Installed Agent never became healthy")

	// A few seconds after the upgrade, deliberately restart upgraded Agent a
	// couple of times to simulate Agent crashing.
	for restartIdx := 0; restartIdx < 3; restartIdx++ {
		time.Sleep(10 * time.Second)
		topPath := paths.Top()

		t.Logf("Restarting Agent via service to simulate crashing")
		err = install.RestartService(topPath)
		require.NoError(t, err)
	}

	// Ensure that the Upgrade Watcher has stopped running.
	waitForUpgradeWatcherToComplete(t, fromF, fromVersionParsed, standaloneWatcherDuration)

	// Ensure that the original version of Agent is running again.
	t.Log("Check Agent version to ensure rollback is successful")
	require.Eventually(t, func() bool {
		return checkAgentHealthAndVersion(t, ctx, fromF, fromVersionParsed.CoreVersion(), false, "")
	}, 2*time.Minute, 10*time.Second, "Installed Agent never became healthy")
}
