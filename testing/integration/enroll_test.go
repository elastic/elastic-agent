// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// //go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
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

func (runner *EnrollRunner) SetupTest() {}

// TestDropMonitoringLogs ensures logs from the monitoring components are not
// sent to the output
func (runner *EnrollRunner) TestDropMonitoringLogs() {
	t := runner.T()
	t.Logf("In TestDropMonitoringLogs")

	defineInfo := runner.requirementsInfo
	kibClient := runner.requirementsInfo.KibanaClient

	// Enroll agent in Fleet with a test policy
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-monitoring-logs-%d", time.Now().Unix()),
		Namespace:   "testdropmonitoringlogs",
		Description: "test policy for drop processors",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: []map[string]interface{}{
			{
				"name":    t.Name(),
				"enabled": true,
			},
		},
	}

	// As part of the cleanup process, we'll uninstall the agent
	policy, err := tools.InstallAgentWithPolicy(t, runner.agentFixture, kibClient, createPolicyReq)
	require.NoError(t, err, "could not install Elastic Agent with Policy")
	t.Logf("created policy: %s", policy.ID)

	t.Cleanup(func() {
		require.NoError(t, tools.UnEnrollAgent(kibClient), "could not un-enroll Elastic-Agent")
	})

	t.Log("waiting 20s so the components can generate some logs and" +
		"Filebeat can collect them")
	time.Sleep(20 * time.Second)
	t.Log("Done sleeping")

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("could not get hostname to filter Agent: %s", err)
	}

	agentID, err := tools.GetAgentIDByHostname(defineInfo.KibanaClient, hostname)
	require.NoError(t, err, "could not get Agent ID by hostname")
	t.Logf("Agent ID: %q", agentID)

	// We cannot search for `component.id` because at the moment of writing
	// this field is not mapped. There is an issue for that:
	// https://github.com/elastic/integrations/issues/6545
	docs, err := tools.GetLogsForAgentID(defineInfo.ESClient, agentID)
	require.NoError(t, err, "could not get logs from Agent ID: %q, err: %s",
		agentID, err)

	monRegExp := regexp.MustCompile(".*-monitoring$")
	for i, d := range docs.Hits.Hits {
		// Lazy way to navigate a map[string]any: convert to JSON then
		// decode into a struct.
		jsonData, err := json.Marshal(d.Source)
		if err != nil {
			t.Fatalf("could not encode document source as JSON: %s", err)
		}

		doc := ESDocument{}
		if err := json.Unmarshal(jsonData, &doc); err != nil {
			t.Fatalf("could not unmarshal document source: %s", err)
		}

		if monRegExp.MatchString(doc.Component.ID) {
			t.Errorf("[%d] Document on index %q with 'component.id': %q "+
				"and 'elastic_agent.id': %q. 'elastic_agent.id' must not "+
				"end in '-monitoring'\n",
				i, d.Index, doc.Component.ID, doc.ElasticAgent.ID)
		}
	}
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
		//After: unenroll
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

type ESDocument struct {
	ElasticAgent ElasticAgent `json:"elastic_agent"`
	Component    Component    `json:"component"`
	Host         Host         `json:"host"`
}
type ElasticAgent struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Snapshot bool   `json:"snapshot"`
}
type Component struct {
	Binary string `json:"binary"`
	ID     string `json:"id"`
}
type Host struct {
	Hostname string `json:"hostname"`
}
