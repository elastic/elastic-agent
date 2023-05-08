//go:build e2e
// +build e2e

package tests

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"

	"github.com/elastic/elastic-agent/pkg/testing/tools"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UpgradeElasticAgent struct {
	suite.Suite
	clusterConfigPath string
	clusterConfig     tools.ClusterConfig
	client            *kibana.Client
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

	kibanaConfig := kibana.ClientConfig{
		Host:     s.clusterConfig.KibanaConfig.Host,
		Username: s.clusterConfig.KibanaConfig.User,
		Password: s.clusterConfig.KibanaConfig.Password,
	}
	s.client, err = kibana.NewClientWithConfig(&kibanaConfig, "elastic-agent-e2e", "", "", "")
	require.Nil(s.T(), err, "Could not create Kibana client")
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
	policy, err := s.client.CreatePolicy(createPolicyReq)
	require.Nil(s.T(), err, "Could not create policy")

	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}
	enrollmentToken, err := s.client.CreateEnrollmentAPIKey(createEnrollmentApiKeyReq)
	require.Nil(s.T(), err, "Could not create enrollment token")

	err = tools.EnrollElasticAgent(s.T(), s.clusterConfig.FleetConfig.Url, enrollmentToken.APIKey, s.agentBinPath)
	require.NoError(s.T(), err)
	require.Nil(s.T(), err, "Error while enrolling elastic agent")

	require.Eventually(s.T(), agentStatus("online", *s), 2*time.Minute, 10*time.Second, "Agent status is not online")

	err = tools.UpgradeAgent(s.client, "8.6.1")
	require.Nil(s.T(), err, "Elastic agent upgrade cmd failed")

	require.Eventually(s.T(), agentStatus("online", *s), 5*time.Minute, 5*time.Second, "Agent status is not online")

	version, err := tools.GetAgentVersion(s.client)
	require.Nil(s.T(), err, "Couldn't get agent ebsion from Fleet")

	require.Equal(s.T(), version, "8.6.1", "Elastic egent version is incorrect")
}

func (s *UpgradeElasticAgent) TearDownTest() {
	s.T().Log("Un-enrolling elastic agent")
	assert.NoError(s.T(), tools.UnEnrollAgent(s.client))
	s.T().Log("Uninstalling elastic agent")
	assert.NoError(s.T(), tools.UninstallAgent(s.T()))
}

func TestElasticAgentUpgrade(t *testing.T) {
	suite.Run(t, new(UpgradeElasticAgent))
}

func agentStatus(expectedStatus string, suite UpgradeElasticAgent) func() bool {
	return func() bool {
		status, err := tools.GetAgentStatus(suite.client)
		if err != nil {
			suite.T().Error(err)
		}
		suite.T().Logf("Agent status: %s", status)
		return status == expectedStatus
	}
}
