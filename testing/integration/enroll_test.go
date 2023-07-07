// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// //go:build integration

package integration

import (
	"fmt"
	"regexp"
	"strings"
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

	t.Logf("In SetupSuite")
	agentFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	t.Logf("In TestEnroll")
	kibClient := info.KibanaClient

	// Fleet API requires the namespace to be lowercased and not contain
	// special characters.
	policyNamespace := strings.ToLower(info.Namespace)
	policyNamespace = regexp.MustCompile("[^a-zA-Z0-9]+").ReplaceAllString(policyNamespace, "")

	// Enroll agent in Fleet with a test policy
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-%d", time.Now().Unix()),
		Namespace:   policyNamespace,
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
	policy, err := tools.InstallAgentWithPolicy(t, agentFixture, kibClient, createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy: %s", policy.ID)

	t.Cleanup(func() {
		// After: unenroll
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
	docs := findESDocs(t, func() (tools.Documents, error) {
		return tools.GetLogsForDatastream(info.ESClient, "elastic_agent.metricbeat")
	})
	require.NotZero(t, len(docs.Hits.Hits))
	t.Logf("metricbeat: Got %d documents", len(docs.Hits.Hits))

	// Stage 4: Make sure filebeat logs are populated
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.GetLogsForDatastream(info.ESClient, "elastic_agent.filebeat")
	})
	require.NotZero(t, len(docs.Hits.Hits))
	t.Logf("Filebeat: Got %d documents", len(docs.Hits.Hits))

	// Stage 5: make sure we have no errors
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.CheckForErrorsInLogs(info.ESClient, []string{})
	})
	t.Logf("errors: Got %d documents", len(docs.Hits.Hits))
	for _, doc := range docs.Hits.Hits {
		t.Logf("%#v", doc.Source)
	}
	require.Empty(t, docs.Hits.Hits)

	// Stage 6: Make sure we have message confirming central management is running
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.FindMatchingLogLines(info.ESClient, "Parsed configuration and determined agent is managed by Fleet")
	})
	require.NotZero(t, len(docs.Hits.Hits))

	// Stage 7: check for starting messages
	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.FindMatchingLogLines(info.ESClient, "metricbeat start running")
	})
	require.NotZero(t, len(docs.Hits.Hits))

	docs = findESDocs(t, func() (tools.Documents, error) {
		return tools.FindMatchingLogLines(info.ESClient, "filebeat start running")
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

	return docs
}
