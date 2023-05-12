// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"

	"github.com/Masterminds/semver"
	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestElasticAgentUpgrade(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	currentVersion := define.Version()
	previousVersion, err := getPreviousMinorVersion(currentVersion)
	require.NoError(t, err)

	suite.Run(t, newUpgradeElasticAgentTestSuite(info, previousVersion, currentVersion))
}

type UpgradeElasticAgent struct {
	suite.Suite

	requirementsInfo  *define.Info
	agentStartVersion string
	agentEndVersion   string
	agentFixture      *atesting.Fixture
}

func newUpgradeElasticAgentTestSuite(info *define.Info, startVersion, endVersion string) *UpgradeElasticAgent {
	return &UpgradeElasticAgent{
		requirementsInfo:  info,
		agentStartVersion: startVersion,
		agentEndVersion:   endVersion,
	}
}

// Before suite
func (s *UpgradeElasticAgent) SetupSuite() {
	agentFixture, err := atesting.NewFixture(
		s.T(),
		s.agentStartVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(s.T(), err)
	s.agentFixture = agentFixture
}

func (s *UpgradeElasticAgent) TestUpgradeFleetManagedElasticAgent() {
	policyUUID := uuid.New().String()

	createPolicyReq := kibana.CreatePolicyRequest{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policy, err := s.requirementsInfo.KibanaClient.CreatePolicy(createPolicyReq)
	require.NoError(s.T(), err)

	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}
	enrollmentToken, err := s.requirementsInfo.KibanaClient.CreateEnrollmentAPIKey(createEnrollmentApiKeyReq)
	require.NoError(s.T(), err)

	// Get default fleet server URL
	fleetServerURL, err := tools.GetDefaultFleetServerURL(s.requirementsInfo.KibanaClient)
	require.NoError(s.T(), err)

	output, err := tools.EnrollElasticAgent(fleetServerURL, enrollmentToken.APIKey, s.agentFixture)
	if err != nil {
		s.T().Log(string(output))
	}
	require.NoError(s.T(), err)

	require.Eventually(s.T(), tools.WaitForAgentStatus(s.T(), s.requirementsInfo.KibanaClient, "online"), 2*time.Minute, 10*time.Second, "Agent status is not online")

	err = tools.UpgradeAgent(s.requirementsInfo.KibanaClient, s.agentEndVersion)
	require.NoError(s.T(), err)

	require.Eventually(s.T(), tools.WaitForAgentStatus(s.T(), s.requirementsInfo.KibanaClient, "online"), 2*time.Minute, 10*time.Second, "Agent status is not online")

	// Wait until the upgrade marker is removed, indicating the end of the
	// upgrade process
	require.Eventually(s.T(), upgradeMarkerRemoved, 10*time.Minute, 20*time.Second)

	newVersion, err := tools.GetAgentVersion(s.requirementsInfo.KibanaClient)
	require.NoError(s.T(), err)
	require.Equal(s.T(), s.agentEndVersion, newVersion)
}

func (s *UpgradeElasticAgent) TearDownTest() {
	s.T().Log("Un-enrolling elastic agent")
	assert.NoError(s.T(), tools.UnEnrollAgent(s.requirementsInfo.KibanaClient))
}

func upgradeMarkerRemoved() bool {
	marker, err := upgrade.LoadMarker()
	if err != nil {
		return false
	}

	return marker == nil
}

func getPreviousMinorVersion(version string) (string, error) {
	v, err := semver.NewVersion(version)
	if err != nil {
		return "", fmt.Errorf("error parsing version [%s]: %w", version, err)
	}

	major := v.Major()
	minor := v.Minor()

	if minor > 0 {
		// We have at least one previous minor version in the current
		// major version series
		return fmt.Sprintf("%d.%d.%d", major, minor-1, 0), nil
	}

	// We are at the first minor of the current major version series. To
	// figure out the previous minor, we need to rely on knowledge of
	// the release versions from the past major series'.
	switch major {
	case 8:
		return "7.17.10", nil
	}

	return "", fmt.Errorf("unable to determine previous minor version for [%s]", version)
}
