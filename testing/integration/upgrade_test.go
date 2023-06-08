// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/version"
)

func TestElasticAgentUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	currentVersion := define.Version()

	// TODO: remove -SNAPSHOT suffix once 8.8.1 is released.
	upgradeFromVersion := "8.8.1-SNAPSHOT"
	upgradeToVersion := currentVersion

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", upgradeFromVersion, upgradeToVersion)
	suite.Run(t, newUpgradeElasticAgentTestSuite(info, upgradeFromVersion, upgradeToVersion))
}

type UpgradeElasticAgent struct {
	suite.Suite

	requirementsInfo *define.Info
	agentFromVersion string
	agentToVersion   string
	agentFixture     *atesting.Fixture
}

func newUpgradeElasticAgentTestSuite(info *define.Info, fromVersion, toVersion string) *UpgradeElasticAgent {
	return &UpgradeElasticAgent{
		requirementsInfo: info,
		agentFromVersion: fromVersion,
		agentToVersion:   toVersion,
	}
}

// Before suite
func (s *UpgradeElasticAgent) SetupSuite() {
	agentFixture, err := atesting.NewFixture(
		s.T(),
		s.agentFromVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(s.T(), err)
	s.agentFixture = agentFixture
}

func (s *UpgradeElasticAgent) TestUpgradeFleetManagedElasticAgent() {
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
	output, err := tools.EnrollElasticAgent(fleetServerURL, enrollmentToken.APIKey, s.agentFixture)
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
	require.Equal(s.T(), s.agentToVersion, newVersion)
}

func (s *UpgradeElasticAgent) TearDownTest() {
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

func TestElasticAgentStandaloneUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		// Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: true,
		Sudo:    true, // requires Agent installation
	})

	testSuite := &UpgradeStandaloneElasticAgent{
		requirementsInfo: info,
		agentVersion:     define.Version(),
	}

	suite.Run(t, testSuite)
}

type UpgradeStandaloneElasticAgent struct {
	suite.Suite

	requirementsInfo *define.Info
	agentVersion     string
	agentFixture     *atesting.Fixture
}

// Before suite
func (s *UpgradeStandaloneElasticAgent) SetupSuite() {

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

func (s *UpgradeStandaloneElasticAgent) TestUpgradeStandaloneElasticAgentToSnapshot() {

	const minVersionString = "8.9.0-SNAPSHOT"
	minVersion, _ := version.ParseVersion(minVersionString)
	pv, err := version.ParseVersion(s.agentVersion)
	if pv.Less(*minVersion) {
		s.T().Skipf("Version %s is lower than min version %s", s.agentVersion, minVersionString)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	output, err := tools.InstallStandaloneElasticAgent(s.agentFixture)
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
