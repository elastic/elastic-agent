// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/Masterminds/semver"
	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/version"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

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

	// TODO: figure out how to get Fleet Server URL
	fleetServerURL := ""
	output, err := tools.EnrollElasticAgent(fleetServerURL, enrollmentToken.APIKey, s.agentFixture)
	if err != nil {
		s.T().Log(string(output))
	}
	require.NoError(s.T(), err)

	require.Eventually(s.T(), agentStatus("online", *s), 2*time.Minute, 10*time.Second, "Agent status is not online")

	err = tools.UpgradeAgent(s.requirementsInfo.KibanaClient, s.agentEndVersion)
	require.NoError(s.T(), err)

	require.Eventually(s.T(), agentStatus("online", *s), 5*time.Minute, 5*time.Second, "Agent status is not online")

	newVersion, err := tools.GetAgentVersion(s.requirementsInfo.KibanaClient)
	require.NoError(s.T(), err)
	require.Equal(s.T(), s.agentEndVersion, newVersion)
}

func (s *UpgradeElasticAgent) TearDownTest() {
	s.T().Log("Un-enrolling elastic agent")
	assert.NoError(s.T(), tools.UnEnrollAgent(s.requirementsInfo.KibanaClient))

	s.T().Log("Uninstalling elastic agent")
	output, err := tools.UninstallAgent(s.agentFixture)
	if err != nil {
		s.T().Log(string(output))
	}
	require.NoError(s.T(), err)
}

func TestElasticAgentUpgrade(t *testing.T) {
	currentVersion := version.GetDefaultVersion()
	previousVersion, err := getPreviousMinorVersion(currentVersion)
	require.NoError(t, err)

	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{Version: currentVersion},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	suite.Run(t, newUpgradeElasticAgentTestSuite(info, previousVersion, currentVersion))
}

func agentStatus(expectedStatus string, suite UpgradeElasticAgent) func() bool {
	return func() bool {
		status, err := tools.GetAgentStatus(suite.requirementsInfo.KibanaClient)
		if err != nil {
			suite.T().Error(err)
		}
		suite.T().Logf("Agent status: %s", status)
		return status == expectedStatus
	}
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
