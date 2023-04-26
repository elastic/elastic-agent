//go:build e2e
// +build e2e

package e2e

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
func (suite *UpgradeElasticAgent) SetupSuite() {
	suite.agentVersion = os.Getenv("AGENT_VERSION")
	require.NotEmpty(suite.T(), suite.agentVersion, "AGENT_VERSION is not set")
	suite.agentBinPath = os.Getenv("AGENT_BIN_PATH")
	require.NotEmpty(suite.T(), suite.agentBinPath, "AGENT_BIN_PATH (path to elastic-agen binary) is not set")

	suite.clusterConfigPath = os.Getenv("CLUSTER_CONFIG_PATH")
	if suite.clusterConfigPath == "" {
		suite.clusterConfigPath = "./cluster-digest.yml"
	}
	var err error
	suite.clusterConfig, err = tools.ReadConfig(suite.clusterConfigPath)
	require.Nil(suite.T(), err, "Could not read cluster config")
	suite.client, err = tools.NewClient(&suite.clusterConfig)
	require.Nil(suite.T(), err, "Could not create Kibana client")
}

func (suite *UpgradeElasticAgent) TestUpgradeFleetManagedElasticAgent() {

	policy, err := suite.client.CreatePolicy(context.Background())
	require.Nil(suite.T(), err, "Could not create policy")
	enrollmentToken, err := suite.client.CreateEnrollmentAPIKey(context.Background(), policy)
	require.Nil(suite.T(), err, "Could not create enrollment token")

	err = tools.EnrollElasticAgent(suite.T(), suite.clusterConfig.FleetConfig.Url, enrollmentToken.APIKey, suite.agentBinPath)
	require.Nil(suite.T(), err, "Error while enrolling elastic agent")

	require.Eventually(suite.T(), agentStatus("online", *suite), 2*time.Minute, 10*time.Second, "Agent status is not online")

	err = suite.client.UpgradeAgent(context.TODO(), "8.6.1")
	require.Nil(suite.T(), err, "Elastic agent upgrade cmd failed")

	require.Eventually(suite.T(), agentStatus("online", *suite), 5*time.Minute, 5*time.Second, "Agent status is not online")

	version, err := suite.client.GetAgentVersion(context.Background())
	require.Nil(suite.T(), err, "Couldn't get agent ebsion from Fleet")

	require.Equal(suite.T(), version, "8.6.1", "Elastic egent version is incorrect")
}

func (suite *UpgradeElasticAgent) TearDownTest() {
	suite.T().Log("Un-enrolling elastic agent")
	assert.NoError(suite.T(), suite.client.UnEnrollAgent(context.Background()))
	suite.T().Log("Uninstalling elastic agent")
	assert.NoError(suite.T(), tools.UninstallAgent(suite.T()))
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
