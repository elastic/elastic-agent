// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

func TestEndpointSecurity(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true,                                                  // requires Agent installation
		OS:      []define.OS{{Type: define.Linux, Arch: define.AMD64}}, // only run on Linux AMD64 during development.
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
	suite.Run(t, newEndpointSecurityTestSuite(info, upgradeFromVersion, upgradeToVersion))
}

type EndpointSecurityTestSuite struct {
	suite.Suite

	requirementsInfo *define.Info
	agentFromVersion string
	agentToVersion   string
	agentFixture     *atesting.Fixture
}

func newEndpointSecurityTestSuite(info *define.Info, fromVersion, toVersion string) *EndpointSecurityTestSuite {
	return &EndpointSecurityTestSuite{
		requirementsInfo: info,
		agentFromVersion: fromVersion,
		agentToVersion:   toVersion,
	}
}

// Before suite
func (s *EndpointSecurityTestSuite) SetupSuite() {
	agentFixture, err := atesting.NewFixture(
		s.T(),
		s.agentFromVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(s.T(), err)
	s.agentFixture = agentFixture
}

func (s *EndpointSecurityTestSuite) TestUpgradeFleetManagedElasticAgent() {
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

func (s *EndpointSecurityTestSuite) TearDownTest() {
	s.T().Log("Un-enrolling Elastic Agent...")
	assert.NoError(s.T(), tools.UnEnrollAgent(s.requirementsInfo.KibanaClient))
}
