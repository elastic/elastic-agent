package e2e_testify

import (
	"fmt"
	"os"
	"testing"
	"time"

	tools "github.com/elastic/elastic-agent/testing/e2e/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UpgradeElasticAgent struct {
	suite.Suite
	clusterConfigPath string
	clusterConfig     tools.ClusterConfig
	client            *tools.Client
	agentVersion      string
}

// Before suite
func (suite *UpgradeElasticAgent) SetupSuite() {
	suite.agentVersion = os.Getenv("AGENT_VERSION")
	assert.NotEmpty(suite.T(), suite.agentVersion, "AGENT_VERSION is not set")

	suite.clusterConfigPath = os.Getenv("CLUSTER_CONFIG_PATH")
	if suite.clusterConfigPath == "" {
		suite.clusterConfigPath = "../cluster-digest.yml"
	}
	var err error
	suite.clusterConfig, err = tools.ReadConfig(suite.clusterConfigPath)
	assert.Nil(suite.T(), err, "Could not read cluster config")
	suite.client, err = tools.NewClient(&suite.clusterConfig)
	assert.Nil(suite.T(), err, "Could not create Kibana client")

	err = tools.DownloadElasticAgent(suite.agentVersion)
	assert.Nil(suite.T(), err, "Could not download Elastic Agent")
}

// before each test
func (suite *UpgradeElasticAgent) SetupTest() {
	suite.T().Log("SetupTest!")
}

func (suite *UpgradeElasticAgent) TestUpgradeFleetManagedElasticAgent() {
	policy, err := suite.client.CreatePolicy()
	assert.Nil(suite.T(), err, "Could not create policy")
	enrollmentToken, err := suite.client.CreateEnrollmentAPIKey(policy)
	assert.Nil(suite.T(), err, "Could not create enrollment token")

	err = tools.EnrollElasticAgent(suite.T(), suite.clusterConfig.FleetConfig.Url, enrollmentToken.APIKey, suite.agentVersion)
	assert.Nil(suite.T(), err, "Error while enrolling elastic agent")

	assert.Eventually(suite.T(), agentStatus("online", *suite), 5*time.Minute, 5*time.Second, "Agent status is not online")

	err = suite.client.UpgradeAgent("8.6.1")
	assert.Nil(suite.T(), err, "Elastic agent upgrade cmd failed")

	assert.Eventually(suite.T(), agentStatus("online", *suite), 5*time.Minute, 5*time.Second, "Agent status is not online")

	version, err := suite.client.GetAgentVersion()
	assert.Nil(suite.T(), err, "Couldn't get agent ebsion from Fleet")

	assert.Equal(suite.T(), version, "8.6.1", "Elastic egent version is incorrect")
}

func (suite *UpgradeElasticAgent) TearDownTest() {
	suite.T().Log("Un-enrolling elastic agent")
	suite.client.UnEnrollAgent()
	suite.T().Log("Uninstalling elastic agent")
	tools.UninstallAgent(suite.T())
}

func TestElasticAgentUpgrade(t *testing.T) {
	suite.Run(t, new(UpgradeElasticAgent))
}

func agentStatus(expectedStatus string, suite UpgradeElasticAgent) func() bool {
	return func() bool {
		status, err := suite.client.GetAgentStatus()
		if err != nil {
			suite.T().Error(err)
		}
		suite.T().Log(fmt.Sprintf("Agent status: %s", status))
		return status == expectedStatus
	}
}
