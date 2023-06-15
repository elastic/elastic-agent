//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/stretchr/testify/suite"

	"github.com/stretchr/testify/require"
)

func TestESHandling(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: true,
	})

	suite.Run(t, &TestES{info: info})
}

type TestES struct {
	suite.Suite
	info *define.Info
}

func (runner *TestES) TestESQuery() {
	resp, err := tools.GetIndices(runner.info.ESClient)
	require.NoError(runner.T(), err)
	for _, run := range resp {
		fmt.Printf("%#v\n", run)
	}
	// req := esapi.CatIndicesRequest{Format: "json"}
	// resp, err := req.Do(context.Background(), runner.info.ESClient.Transport)
	// require.NoError(runner.T(), err)
	// require.Equal(runner.T(), 200, resp.StatusCode)
	// buf, err := io.ReadAll(resp.Body)
	// require.NoError(runner.T(), err)
	// fmt.Printf("Got response from ES: %#v\n", string(buf))
	// fmt.Printf("Got header: %#v\n", resp.Header)
}

func TestEnrollAndLog(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})
	fmt.Printf("Got namespace: %s\n", info.Namespace)
	t.Logf("got namespace: %s", info.Namespace)
	suite.Run(t, &EnrollRunner{requirementsInfo: info})
}

type EnrollRunner struct {
	suite.Suite
	requirementsInfo *define.Info
	agentFixture     *atesting.Fixture
}

func (runner *EnrollRunner) SetupSuite() {
	runner.T().Logf("In SetupSuite")
	agentFixture, err := define.NewFixture(runner.T())
	runner.agentFixture = agentFixture
	require.NoError(runner.T(), err)
}

func (runner *EnrollRunner) SetupTest() {

}

func (runner *EnrollRunner) TestEnroll() {
	runner.T().Logf("In TestEnroll")
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
	policy, err := tools.InstallAgentWithPolicy(runner.T(), runner.agentFixture, kibClient, createPolicyReq)
	require.NoError(runner.T(), err)
	runner.T().Logf("got policy: %#v", policy)

	req := esapi.CatIndicesRequest{}
	resp, err := req.Do(context.Background(), runner.requirementsInfo.ESClient.Transport)
	require.NoError(runner.T(), err)
	fmt.Printf("Got response from ES: %#v\n", resp)
}
