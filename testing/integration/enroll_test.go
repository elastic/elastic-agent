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

	t.Skip("Test is flaky; see https://github.com/elastic/elastic-agent/issues/3081")

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

func (runner *EnrollRunner) TestEnroll() {
	t := runner.T()
	info := runner.requirementsInfo

	kibClient := info.KibanaClient

	t.Log("Enrolling agent in Fleet with a test policy")
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-%d", time.Now().Unix()),
		Namespace:   info.Namespace,
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
	policy, err := tools.InstallAgentWithPolicy(t, runner.agentFixture, kibClient, createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy: %s", policy.ID)

	t.Cleanup(func() {
		//After: unenroll
		t.Logf("Cleanup: unenrolling agent")
		err = tools.UnEnrollAgent(info.KibanaClient)
		require.NoError(t, err)
	})

	t.Logf("sleeping for one minute...")
	time.Sleep(time.Second * 60)

	// Stage 2: check indicies
	// This is mostly for debugging
	resp, err := tools.GetAllindicies(info.ESClient)
	require.NoError(t, err)
	for _, run := range resp {
		t.Logf("%s: %d/%d deleted: %d\n", run.Index, run.DocsCount, run.StoreSizeBytes, run.DocsDeleted)
	}

	// Stage 3: Make sure metricbeat logs are populated
	t.Log("Making sure metricbeat logs are populated")
	docs := findESDocs(t, func() (tools.Documents, error) {
		return tools.GetLogsForDatastream(info.ESClient, "elastic_agent.metricbeat")
	})
	require.NotZero(t, len(docs.Hits.Hits))
	t.Logf("metricbeat: Got %d documents", len(docs.Hits.Hits))

	// Stage 4: make sure we have no errors
	t.Log("Making sure there are no error logs")
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.CheckForErrorsInLogs(info.ESClient, info.Namespace, []string{})
	})
	t.Logf("errors: Got %d documents", len(docs.Hits.Hits))
	for _, doc := range docs.Hits.Hits {
		t.Logf("%#v", doc.Source)
	}
	require.Empty(t, docs.Hits.Hits)

	// Stage 5: Make sure we have message confirming central management is running
	t.Log("Making sure we have message confirming central management is running")
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.FindMatchingLogLines(info.ESClient, info.Namespace, "Parsed configuration and determined agent is managed by Fleet")
	})
	require.NotZero(t, len(docs.Hits.Hits))

	// Stage 6: verify logs from the monitoring components are not sent to the output
	t.Log("Check monitoring logs")
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("could not get hostname to filter Agent: %s", err)
	}

	agentID, err := tools.GetAgentIDByHostname(info.KibanaClient, hostname)
	require.NoError(t, err, "could not get Agent ID by hostname")
	t.Logf("Agent ID: %q", agentID)

	// We cannot search for `component.id` because at the moment of writing
	// this field is not mapped. There is an issue for that:
	// https://github.com/elastic/integrations/issues/6545

	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.GetLogsForAgentID(info.ESClient, agentID)
	})
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

func findESDocs(t *testing.T, findFn func() (tools.Documents, error)) tools.Documents {
	var docs tools.Documents

	require.Eventually(
		t,
		func() bool {
			var err error
			docs, err = findFn()
			return err == nil
		},
		3*time.Minute,
		15*time.Second,
	)

	// TODO: remove after debugging
	t.Log("--- debugging: results from ES --- START ---")
	for _, doc := range docs.Hits.Hits {
		t.Logf("%#v", doc.Source)
	}
	t.Log("--- debugging: results from ES --- END ---")

	return docs
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
