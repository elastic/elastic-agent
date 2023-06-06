// //go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/stretchr/testify/suite"

	"github.com/stretchr/testify/require"
)

func TestEnrollAndLog(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
	})
	t.Logf("got namespace: %s", info.Namespace)
	suite.Run(t, &EnrollRunner{requirementsInfo: info})
}

type EnrollRunner struct {
	suite.Suite
	requirementsInfo *define.Info
	agentFixture     *atesting.Fixture
}

func (runner *EnrollRunner) SetupSuite() {
	agentFixture, err := define.NewFixture(runner.T())
	runner.agentFixture = agentFixture
	require.NoError(runner.T(), err)
}

func (runner *EnrollRunner) SetupTest() {

}

func (runner *EnrollRunner) TestEnroll() {
	kibClient := runner.requirementsInfo.KibanaClient
	// Enroll agent in Fleet with a test policy
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-%d", time.Now().Unix()),
		Namespace:   "enrolltest",
		Description: "test policy for agent enrollment",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: []map[string]interface{}{
			{
				"name":    "test_enroll",
				"enabled": true,
			},
		},
	}
	policy, err := tools.EnrollAgentWithPolicy(runner.T(), true, runner.agentFixture, kibClient, createPolicyReq)
	require.NoError(runner.T(), err)
	runner.T().Logf("got policy: %#v", policy)
}
