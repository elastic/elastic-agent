// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// //go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"

	"github.com/stretchr/testify/require"
)

func TestEnrollAndLog(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
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
	runner.T().Logf("In SetupSuite")
	agentFixture, err := define.NewFixture(runner.T(), define.Version())
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
	// As part of the cleanup process, we'll uninstall the agent
	policy, err := tools.InstallAgentWithPolicy(runner.T(), runner.agentFixture, kibClient, createPolicyReq)
	require.NoError(runner.T(), err)
	runner.T().Logf("created policy: %s", policy.ID)

	runner.T().Cleanup(func() {
		// After: unenroll
		err = tools.UnEnrollAgent(runner.requirementsInfo.KibanaClient)
		require.NoError(runner.T(), err)
	})

	runner.T().Logf("sleeping for one minute...")
	time.Sleep(time.Second * 60)

	// Stage 2: check indicies
	// This is mostly for debugging
	resp, err := tools.GetAllindicies(runner.requirementsInfo.ESClient)
	require.NoError(runner.T(), err)
	for _, run := range resp {
		runner.T().Logf("%s: %d/%d deleted: %d\n", run.Index, run.DocsCount, run.StoreSizeBytes, run.DocsDeleted)
	}

	// Stage 3: Make sure metricbeat logs are populated
	docs, err := tools.GetLogsForDatastream(runner.requirementsInfo.ESClient, "elastic_agent.metricbeat")
	require.NoError(runner.T(), err)
	require.NotZero(runner.T(), len(docs.Hits.Hits))
	runner.T().Logf("metricbeat: Got %d documents", len(docs.Hits.Hits))

	// Stage 4: Make sure filebeat logs are populated
	docs, err = tools.GetLogsForDatastream(runner.requirementsInfo.ESClient, "elastic_agent.filebeat")
	require.NoError(runner.T(), err)
	require.NotZero(runner.T(), len(docs.Hits.Hits))
	runner.T().Logf("Filebeat: Got %d documents", len(docs.Hits.Hits))

	// Stage 5: make sure we have no errors
	docs, err = tools.CheckForErrorsInLogs(runner.requirementsInfo.ESClient, []string{})
	require.NoError(runner.T(), err)
	runner.T().Logf("errors: Got %d documents", len(docs.Hits.Hits))
	for _, doc := range docs.Hits.Hits {
		runner.T().Logf("%#v", doc.Source)
	}
	require.Empty(runner.T(), docs.Hits.Hits)

	// Stage 6: Make sure we have message confirming central management is running
	docs, err = tools.FindMatchingLogLines(runner.requirementsInfo.ESClient, "Parsed configuration and determined agent is managed by Fleet")
	require.NoError(runner.T(), err)
	require.NotZero(runner.T(), len(docs.Hits.Hits))

	// Stage 7: check for starting messages
	docs, err = tools.FindMatchingLogLines(runner.requirementsInfo.ESClient, "metricbeat start running")
	require.NoError(runner.T(), err)
	require.NotZero(runner.T(), len(docs.Hits.Hits))

	docs, err = tools.FindMatchingLogLines(runner.requirementsInfo.ESClient, "filebeat start running")
	require.NoError(runner.T(), err)
	require.NotZero(runner.T(), len(docs.Hits.Hits))

}
