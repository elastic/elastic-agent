// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
)

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
	suite.Run(t, newFleetManagedUpgradeTestSuite(info, upgradeFromVersion, upgradeToVersion))
}

type FleetManagedUpgradeTestSuite struct {
	suite.Suite

	requirementsInfo *define.Info
	agentFromVersion string
	agentToVersion   string
	agentFixture     *atesting.Fixture
}

func newFleetManagedUpgradeTestSuite(info *define.Info, fromVersion, toVersion string) *FleetManagedUpgradeTestSuite {
	return &FleetManagedUpgradeTestSuite{
		requirementsInfo: info,
		agentFromVersion: fromVersion,
		agentToVersion:   toVersion,
	}
}

// Before suite
func (s *FleetManagedUpgradeTestSuite) SetupSuite() {
	agentFixture, err := atesting.NewFixture(
		s.T(),
		s.agentFromVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(s.T(), err)
	s.agentFixture = agentFixture
}

func (s *FleetManagedUpgradeTestSuite) TestUpgradeFleetManagedElasticAgent() {
	kibClient := s.requirementsInfo.KibanaClient
	policyUUID := uuid.New().String()

	s.T().Log("Creating Agent policy...")
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
	require.NoError(s.T(), err)

	s.T().Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(createEnrollmentApiKeyReq)
	require.NoError(s.T(), err)

	s.T().Log("Getting default Fleet Server URL...")
	fleetServerURL, err := tools.GetDefaultFleetServerURL(kibClient)
	require.NoError(s.T(), err)

	s.T().Log("Enrolling Elastic Agent...")
	output, err := tools.InstallAgent(fleetServerURL, enrollmentToken.APIKey, s.agentFixture)
	if err != nil {
		s.T().Log(string(output))
	}
	require.NoError(s.T(), err)

	s.T().Log(`Waiting for enrolled Agent status to be "online"...`)
	require.Eventually(s.T(), tools.WaitForAgentStatus(s.T(), kibClient, "online"), 2*time.Minute, 10*time.Second, "Agent status is not online")

	s.T().Logf("Upgrade Elastic Agent to version %s...", s.agentToVersion)
	err = tools.UpgradeAgent(kibClient, s.agentToVersion)
	require.NoError(s.T(), err)

	s.T().Log(`Waiting for enrolled Agent status to be "online"...`)
	require.Eventually(s.T(), tools.WaitForAgentStatus(s.T(), kibClient, "online"), 3*time.Minute, 15*time.Second, "Agent status is not online")

	s.T().Log("Waiting for upgrade marker to be removed...")
	require.Eventually(s.T(), upgradeMarkerRemoved, 10*time.Minute, 20*time.Second)

	s.T().Log("Getting Agent version...")
	newVersion, err := tools.GetAgentVersion(kibClient)
	require.NoError(s.T(), err)

	// We remove the `-SNAPSHOT` suffix because, post-upgrade, the version reported
	// by the Agent will not contain this suffix, even if a `-SNAPSHOT`-suffixed
	// version was used as the target version for the upgrade.
	require.Equal(s.T(), strings.TrimRight(s.agentToVersion, `-SNAPSHOT`), newVersion)
}

func (s *FleetManagedUpgradeTestSuite) TearDownTest() {
	s.T().Log("Un-enrolling Elastic Agent...")
	assert.NoError(s.T(), tools.UnEnrollAgent(s.requirementsInfo.KibanaClient))
}

func upgradeMarkerRemoved() bool {
	marker, err := upgrade.LoadMarker()
	if err != nil {
		return false
	}

	return marker == nil
}

func TestStandaloneUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		// Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: true,
		Sudo:    true, // requires Agent installation
	})

	testSuite := &StandaloneUpgradeTestSuite{
		requirementsInfo: info,
		agentVersion:     define.Version(),
	}

	suite.Run(t, testSuite)
}

type StandaloneUpgradeTestSuite struct {
	suite.Suite

	requirementsInfo *define.Info
	agentVersion     string
	agentFixture     *atesting.Fixture
}

// Before suite
func (s *StandaloneUpgradeTestSuite) SetupSuite() {

	agentFixture, err := define.NewFixture(
		s.T(),
	)

	require.NoError(s.T(), err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = agentFixture.Prepare(ctx)
	s.Require().NoError(err, "error preparing agent fixture")
	s.agentFixture = agentFixture
}

func (s *StandaloneUpgradeTestSuite) TestUpgradeStandaloneElasticAgentToSnapshot() {

	const minVersionString = "8.9.0-SNAPSHOT"
	minVersion, _ := version.ParseVersion(minVersionString)
	pv, err := version.ParseVersion(s.agentVersion)
	if pv.Less(*minVersion) {
		s.T().Skipf("Version %s is lower than min version %s", s.agentVersion, minVersionString)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	output, err := tools.InstallStandaloneAgent(s.agentFixture)
	s.T().Logf("Agent installation output: %q", string(output))
	require.NoError(s.T(), err)

	c := s.agentFixture.Client()

	require.Eventually(s.T(), func() bool {
		err := c.Connect(ctx)
		if err != nil {
			s.T().Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			s.T().Logf("error getting the agent state: %v", err)
			return false
		}
		s.T().Logf("agent state: %+v", state)
		return state.State == cproto.State_HEALTHY
	}, 2*time.Minute, 10*time.Second, "Agent never became healthy")

	aac := tools.NewArtifactAPIClient()
	vList, err := aac.GetVersions(ctx)
	s.Require().NoError(err, "error retrieving versions from Artifact API")
	s.Require().NotNil(vList)

	sortedParsedVersions := make(version.SortableParsedVersions, 0, len(vList.Versions))
	for _, v := range vList.Versions {
		pv, err := version.ParseVersion(v)
		s.Require().NoErrorf(err, "invalid version retrieved from artifact API: %q", v)
		sortedParsedVersions = append(sortedParsedVersions, pv)
	}

	s.Require().NotEmpty(sortedParsedVersions)

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

	s.Require().NotNil(latestSnapshotVersion)

	// get all the builds of the snapshot version (need to pass x.y.z-SNAPSHOT format)
	builds, err := aac.GetBuildsForVersion(ctx, latestSnapshotVersion.VersionWithPrerelease())
	s.Require().NoError(err)
	// TODO if we don't have at least 2 builds, select the next older snapshot build
	s.Require().Greater(len(builds.Builds), 1)

	// take the penultimate build of the snapshot (the builds are ordered from most to least recent)
	upgradeVersionString := builds.Builds[1]

	s.T().Logf("Targeting build %q of version %q", upgradeVersionString, latestSnapshotVersion)

	buildDetails, err := aac.GetBuildDetails(ctx, latestSnapshotVersion.VersionWithPrerelease(), upgradeVersionString)
	s.Require().NoErrorf(err, "error accessing build details for version %q and buildID %q", latestSnapshotVersion.Original(), upgradeVersionString)
	s.Require().NotNil(buildDetails)
	agentBuildDetails, ok := buildDetails.Build.Projects["elastic-agent"]
	s.Require().Truef(ok, "elastic agent project not found in version %q build %q", latestSnapshotVersion.Original(), upgradeVersionString)

	expectedAgentHashAfterUpgrade := agentBuildDetails.CommitHash

	buildFragments := strings.Split(upgradeVersionString, "-")
	s.Require().Lenf(buildFragments, 2, "version %q returned by artifact api is not in format <version>-<buildID>", upgradeVersionString)

	upgradeInputVersion := version.NewParsedSemVer(
		latestSnapshotVersion.Major(),
		latestSnapshotVersion.Minor(),
		latestSnapshotVersion.Patch(),
		latestSnapshotVersion.Prerelease(),
		buildFragments[1],
	)

	s.T().Logf("Upgrading to version %q", upgradeInputVersion)

	err = c.Connect(ctx)
	s.Require().NoError(err, "error connecting client to agent")
	defer c.Disconnect()

	_, err = c.Upgrade(ctx, upgradeInputVersion.String(), "", false)
	s.Require().NoErrorf(err, "error triggering agent upgrade to version %q", upgradeInputVersion.String())

	s.Require().Eventuallyf(func() bool {
		state, err := c.State(ctx)
		if err != nil {
			s.T().Logf("error getting the agent state: %v", err)
			return false
		}
		s.T().Logf("current agent state: %+v", state)
		return state.Info.Commit == expectedAgentHashAfterUpgrade && state.State == cproto.State_HEALTHY
	}, 10*time.Minute, 1*time.Second, "agent never upgraded to expected version")

	updateMarkerFile := filepath.Join(paths.DefaultBasePath, "Elastic", "Agent", "data", ".update-marker")

	s.Require().FileExists(updateMarkerFile)

	// The checks of the update marker makes the test time out since it runs for more than 10 minutes :(
	// A dedicated issue to address this has been opened: https://github.com/elastic/elastic-agent/issues/2796

	// s.Require().Eventuallyf(func() bool {
	// 	_, err := os.Stat(updateMarkerFile)
	// 	return errors.Is(err, fs.ErrNotExist)
	// }, 10*time.Minute, 1*time.Second, "agent never removed update marker")

	// version, err := c.Version(ctx)
	// s.Require().NoError(err, "error checking version after upgrade")
	// s.Require().Equal(expectedAgentHashAfterUpgrade, version.Commit, "agent commit hash changed after upgrade")
}

func TestStandaloneUpgradeRetryDownload(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation and modifying /etc/hosts
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		}, // modifying /etc/hosts
	})

	currentVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	previousVersion, err := currentVersion.GetPreviousMinor()
	require.NoError(t, err)

	// For testing the upgrade we actually perform a downgrade
	upgradeFromVersion := currentVersion
	upgradeToVersion := previousVersion

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", upgradeFromVersion, upgradeToVersion)
	suite.Run(t, newStandaloneUpgradeRetryDownloadTestSuite(info, upgradeToVersion))
}

type StandaloneUpgradeRetryDownloadTestSuite struct {
	suite.Suite

	requirementsInfo *define.Info
	toVersion        *version.ParsedSemVer
	agentFixture     *atesting.Fixture

	isEtcHostsModified bool
}

type versionInfo struct {
	Version string `yaml:"version"`
	Commit  string `yaml:"commit"`
}

type versionOutput struct {
	Binary versionInfo `yaml:"binary"`
	Daemon versionInfo `yaml:"daemon"`
}

func newStandaloneUpgradeRetryDownloadTestSuite(info *define.Info, toVersion *version.ParsedSemVer) *StandaloneUpgradeRetryDownloadTestSuite {
	return &StandaloneUpgradeRetryDownloadTestSuite{
		requirementsInfo: info,
		toVersion:        toVersion,
	}
}

// Before suite
func (s *StandaloneUpgradeRetryDownloadTestSuite) SetupSuite() {
	agentFixture, err := define.NewFixture(
		s.T(),
	)
	s.Require().NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = agentFixture.Prepare(ctx)
	s.Require().NoError(err, "error preparing agent fixture")
	s.agentFixture = agentFixture
}

func (s *StandaloneUpgradeRetryDownloadTestSuite) TestUpgradeStandaloneElasticAgentRetryDownload() {
	ctx := context.Background()

	s.T().Log("Install the built Agent")
	output, err := tools.InstallStandaloneAgent(s.agentFixture)
	s.T().Log(string(output))
	s.Require().NoError(err)

	s.T().Log("Ensure the correct version is running")
	currentVersion, err := s.getVersion(ctx)
	s.Require().NoError(err)

	s.T().Log("Modify /etc/hosts to simulate transient network error")
	cmd := exec.Command("sed",
		"-i.bak",
		"s/localhost/localhost artifacts.elastic.co artifacts-api.elastic.co/g",
		"/etc/hosts",
	)
	s.T().Log("/etc/hosts modify command: ", cmd.String())

	output, err = cmd.CombinedOutput()
	if err != nil {
		s.T().Log(string(output))
	}
	s.Require().NoError(err)

	// Ensure that /etc/hosts is modified
	s.Eventually(func() bool {
		cmd := exec.Command("grep",
			"artifacts",
			"/etc/hosts",
		)
		s.T().Log("Check /etc/hosts command: ", cmd.String())

		// We don't check the error as grep will return non-zero exit code when
		// it doesn't find any matches, which could happen the first couple of
		// times it searches /etc/hosts.
		output, _ := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		return outputStr != ""
	}, 10*time.Second, 1*time.Second)

	s.isEtcHostsModified = true
	defer s.restoreEtcHosts()

	s.T().Log("Start the Agent upgrade")
	var toVersion = s.toVersion.String()
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)

		err := s.upgradeAgent(ctx, toVersion)

		wg.Done()
		s.Require().NoError(err)
	}()

	s.T().Log("Check Agent logs for at least two retry messages")
	agentDirName := fmt.Sprintf("elastic-agent-%s", release.TrimCommit(currentVersion.Daemon.Commit))
	logsPath := filepath.Join(paths.DefaultBasePath, "Elastic", "Agent", "data", agentDirName, "logs")
	s.Eventually(func() bool {
		cmd := exec.Command("grep",
			"download.*retrying",
			"--recursive",
			"--include", "*.ndjson",
			logsPath,
		)
		s.T().Log("Find logs command: ", cmd.String())

		// We don't check the error as grep will return non-zero exit code when
		// it doesn't find any matches, which could happen the first couple of
		// times it searches the Elastic Agent logs.
		output, _ := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		outputLines := strings.Split(outputStr, "\n")
		s.T().Log(outputLines)
		s.T().Log("Number of retry messages: ", len(outputLines))
		return len(outputLines) >= 2
	}, 2*time.Minute, 20*time.Second)

	s.T().Log("Restore /etc/hosts so upgrade can proceed")
	s.restoreEtcHosts()

	// Wait for upgrade command to finish executing
	s.T().Log("Waiting for upgrade to finish")
	wg.Wait()

	s.T().Log("Check Agent version to ensure upgrade is successful")
	currentVersion, err = s.getVersion(ctx)
	s.Require().NoError(err)
	s.Require().Equal(toVersion, currentVersion.Binary.Version)
	s.Require().Equal(toVersion, currentVersion.Daemon.Version)
}

func (s *StandaloneUpgradeRetryDownloadTestSuite) getVersion(ctx context.Context) (*versionOutput, error) {
	var currentVersion versionOutput
	var err error

	s.Eventually(func() bool {
		args := []string{"version", "--yaml"}
		var output []byte
		output, err = s.agentFixture.Exec(ctx, args)
		if err != nil {
			s.T().Log(string(output))
			return false
		}

		err = yaml.Unmarshal(output, &currentVersion)
		return err == nil
	}, 1*time.Minute, 1*time.Second)

	return &currentVersion, err
}

func (s *StandaloneUpgradeRetryDownloadTestSuite) restoreEtcHosts() {
	if !s.isEtcHostsModified {
		return
	}

	cmd := exec.Command("mv",
		"/etc/hosts.bak",
		"/etc/hosts",
	)
	err := cmd.Run()
	s.Require().NoError(err)
	s.isEtcHostsModified = false
}

func (s *StandaloneUpgradeRetryDownloadTestSuite) upgradeAgent(ctx context.Context, version string) error {
	args := []string{"upgrade", version}
	output, err := s.agentFixture.Exec(ctx, args)
	if err != nil {
		s.T().Log("Upgrade command output after error: ", string(output))
		return err
	}

	return nil
}
