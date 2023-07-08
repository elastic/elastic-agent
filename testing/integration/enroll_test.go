// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// //go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
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

	agentFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

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

	// As part of the cleanup process, we'll uninstall the agent
	policy, err := tools.InstallAgentWithPolicy(t, agentFixture, kibClient, createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy: %s", policy.ID)

	t.Cleanup(func() {
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

	t.Log("Making sure metricbeat logs are populated")
	docs := findESDocs(t, func() (tools.Documents, error) {
		return tools.GetLogsForDatastream(info.ESClient, "elastic_agent.metricbeat")
	})
	require.NotZero(t, len(docs.Hits.Hits))
	t.Logf("metricbeat: Got %d documents", len(docs.Hits.Hits))

	t.Log("Making sure filebeat logs are populated")
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.GetLogsForDatastream(info.ESClient, "elastic_agent.filebeat")
	})
	require.NotZero(t, len(docs.Hits.Hits))
	t.Logf("Filebeat: Got %d documents", len(docs.Hits.Hits))

	t.Log("Making sure there are no error logs")
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.CheckForErrorsInLogs(info.ESClient, info.Namespace, []string{})
	})
	t.Logf("errors: Got %d documents", len(docs.Hits.Hits))
	for _, doc := range docs.Hits.Hits {
		t.Logf("%#v", doc.Source)
	}
	require.Empty(t, docs.Hits.Hits)

	t.Log("Making sure we have message confirming central management is running")
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.FindMatchingLogLines(info.ESClient, info.Namespace, "Parsed configuration and determined agent is managed by Fleet")
	})
	require.NotZero(t, len(docs.Hits.Hits))

	t.Log("Check for metricbeat starting message")
	// Stage 7: check for starting messages
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.FindMatchingLogLines(info.ESClient, info.Namespace, "metricbeat start running")
	})
	require.NotZero(t, len(docs.Hits.Hits))

	t.Log("Check for filebeat starting message")
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.FindMatchingLogLines(info.ESClient, info.Namespace, "filebeat start running")
	})
	require.NotZero(t, len(docs.Hits.Hits))
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
