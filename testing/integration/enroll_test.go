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
	resp, err := tools.GetAllindicies(runner.info.ESClient)
	require.NoError(runner.T(), err)
	for _, run := range resp {
		fmt.Printf("%#v\n", run)
	}

	docs, err := tools.GetLogsForDatastream(runner.info.ESClient, "elastic_agent.metricbeat")
	require.NoError(runner.T(), err)
	runner.T().Logf("Got %d documents", len(docs.Hits.Hits))
	for _, doc := range docs.Hits.Hits {
		fmt.Printf("%#v\n", doc)
	}
	runner.T().Logf("Raw: %#v", docs)
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
	// Stage 1: Install
	policy, err := tools.InstallAgentWithPolicy(runner.T(), runner.agentFixture, kibClient, runner.requirementsInfo.ESClient, createPolicyReq)
	require.NoError(runner.T(), err)
	runner.T().Logf("created policy: %s", policy.ID)

	runner.T().Logf("sleeping for one minute...")
	time.Sleep(time.Second * 60)

	// Stage 2:
	resp, err := tools.GetAllindicies(runner.requirementsInfo.ESClient)
	require.NoError(runner.T(), err)
	for _, run := range resp {
		fmt.Printf("%s: %d/%d deleted: %d\n", run.Index, run.DocsCount, run.StoreSizeBytes, run.DocsDeleted)
	}

	docs, err := tools.GetLogsForDatastream(runner.requirementsInfo.ESClient, "elastic_agent.metricbeat")
	require.NoError(runner.T(), err)
	runner.T().Logf("Got %d documents", len(docs.Hits.Hits))
	for _, doc := range docs.Hits.Hits {
		fmt.Printf("%#v\n", doc)
	}
	runner.T().Logf("Raw: %#v", docs)
}
