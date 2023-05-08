//go:build e2e
// +build e2e

package tests

import (
	"context"
	"os"
	"testing"
	"time"

	tools "github.com/elastic/elastic-agent/testing/e2e/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UpgradeElasticAgent struct {
	suite.Suite
	clusterConfigPath string
	clusterConfig     tools.ClusterConfig
	client            *tools.Client
	agentVersion      string
	agentBinPath      string
}

// Before suite
func (s *UpgradeElasticAgent) SetupSuite() {
	s.agentVersion = os.Getenv("AGENT_VERSION")
	require.NotEmpty(s.T(), s.agentVersion, "AGENT_VERSION is not set")
	s.agentBinPath = os.Getenv("AGENT_BIN_PATH")
	require.NotEmpty(s.T(), s.agentBinPath, "AGENT_BIN_PATH (path to elastic-agent binary) is not set")

	s.clusterConfigPath = os.Getenv("CLUSTER_CONFIG_PATH")
	if s.clusterConfigPath == "" {
		s.clusterConfigPath = "../cluster-digest.yml"
	}
	var err error
	s.clusterConfig, err = tools.ReadConfig(s.clusterConfigPath)
	require.Nil(s.T(), err, "Could not read cluster config")
	s.client, err = tools.NewClient(&s.clusterConfig)
	require.Nil(s.T(), err, "Could not create Kibana client")
}

func (s *UpgradeElasticAgent) TestUpgradeFleetManagedElasticAgent() {

	policy, err := s.client.CreatePolicy(context.Background())
	require.Nil(s.T(), err, "Could not create policy")
	enrollmentToken, err := s.client.CreateEnrollmentAPIKey(context.Background(), policy)
	require.Nil(s.T(), err, "Could not create enrollment token")

	err = tools.EnrollElasticAgent(s.T(), s.clusterConfig.FleetConfig.Url, enrollmentToken.APIKey, s.agentBinPath)
	require.NoError(s.T(), err)
	require.Nil(s.T(), err, "Error while enrolling elastic agent")

	require.Eventually(s.T(), agentStatus("online", *s), 2*time.Minute, 10*time.Second, "Agent status is not online")

	err = s.client.UpgradeAgent(context.TODO(), "8.6.1")
	require.Nil(s.T(), err, "Elastic agent upgrade cmd failed")

	require.Eventually(s.T(), agentStatus("online", *s), 5*time.Minute, 5*time.Second, "Agent status is not online")

	version, err := s.client.GetAgentVersion(context.Background())
	require.Nil(s.T(), err, "Couldn't get agent ebsion from Fleet")

	require.Equal(s.T(), version, "8.6.1", "Elastic egent version is incorrect")
}

func (s *UpgradeElasticAgent) TearDownTest() {
	s.T().Log("Un-enrolling elastic agent")
	assert.NoError(s.T(), s.client.UnEnrollAgent(context.Background()))
	s.T().Log("Uninstalling elastic agent")
	assert.NoError(s.T(), tools.UninstallAgent(s.T()))
}

func TestElasticAgentUpgrade(t *testing.T) {
	suite.Run(t, new(UpgradeElasticAgent))
}

func agentStatus(expectedStatus string, suite UpgradeElasticAgent) func() bool {
	return func() bool {
		status, err := suite.client.GetAgentStatus(context.Background())
		if err != nil {
			suite.T().Error(err)
		}
		suite.T().Logf("Agent status: %s", status)
		return status == expectedStatus
	}
}
