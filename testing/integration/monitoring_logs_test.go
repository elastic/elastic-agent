// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

func TestLogIngestionFleetManaged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})
	ctx := context.Background()

	agentFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// 1. Create a policy in Fleet with monitoring enabled.
	// To ensure there are no conflicts with previous test runs against
	// the same ESS stack, we add the current time at the end of the policy
	// name. This policy does not contain any integration.
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

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}

	// 2. Install the Elastic-Agent with the policy that
	// was just created.
	policy, err := tools.InstallAgentWithPolicy(
		ctx,
		t,
		installOpts,
		agentFixture,
		info.KibanaClient,
		createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy: %s", policy.ID)
	check.ConnectedToFleet(t, agentFixture, 5*time.Minute)

	t.Run("Monitoring logs are shipped", func(t *testing.T) {
		testMonitoringLogsAreShipped(t, ctx, info, agentFixture, policy)
	})

	t.Run("Normal logs with flattened data_stream are shipped", func(t *testing.T) {
		testFlattenedDatastreamFleetPolicy(t, ctx, info, agentFixture, policy)
	})
}

func testMonitoringLogsAreShipped(
	t *testing.T,
	ctx context.Context,
	info *define.Info,
	agentFixture *atesting.Fixture,
	policy kibana.PolicyResponse,
) {
	// Stage 1: Make sure metricbeat logs are populated
	t.Log("Making sure metricbeat logs are populated")
	docs := findESDocs(t, func() (estools.Documents, error) {
		return estools.GetLogsForDataset(info.ESClient, "elastic_agent.metricbeat")
	})
	t.Logf("metricbeat: Got %d documents", len(docs.Hits.Hits))
	require.NotZero(t, len(docs.Hits.Hits))

	// Stage 2: make sure all components are healthy
	t.Log("Making sure all components are healthy")
	status, err := agentFixture.ExecStatus(ctx)
	require.NoError(t, err,
		"could not get agent status to verify all components are healthy")
	for _, c := range status.Components {
		assert.Equalf(t, client.Healthy, client.State(c.State),
			"component %s: want %s, got %s",
			c.Name, client.Healthy, client.State(c.State))
	}

	// Stage 3: Make sure there are no errors in logs
	t.Log("Making sure there are no error logs")
	docs = findESDocs(t, func() (estools.Documents, error) {
		return estools.CheckForErrorsInLogs(info.ESClient, info.Namespace, []string{
			// acceptable error messages (include reason)
			"Error dialing dial tcp 127.0.0.1:9200: connect: connection refused", // beat is running default config before its config gets updated
			"Global configuration artifact is not available",                     // Endpoint: failed to load user artifact due to connectivity issues
			"Failed to download artifact",
			"Failed to initialize artifact",
			"Failed to apply initial policy from on disk configuration",
			"elastic-agent-client error: rpc error: code = Canceled desc = context canceled", // can happen on restart
		})
	})
	t.Logf("errors: Got %d documents", len(docs.Hits.Hits))
	for _, doc := range docs.Hits.Hits {
		t.Logf("%#v", doc.Source)
	}
	require.Empty(t, docs.Hits.Hits)

	// Stage 4: Make sure we have message confirming central management is running
	t.Log("Making sure we have message confirming central management is running")
	docs = findESDocs(t, func() (estools.Documents, error) {
		return estools.FindMatchingLogLines(info.ESClient, info.Namespace,
			"Parsed configuration and determined agent is managed by Fleet")
	})
	require.NotZero(t, len(docs.Hits.Hits))

	// Stage 5: verify logs from the monitoring components are not sent to the output
	t.Log("Check monitoring logs")
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("could not get hostname to filter Agent: %s", err)
	}

	agentID, err := fleettools.GetAgentIDByHostname(info.KibanaClient, policy.ID, hostname)
	require.NoError(t, err, "could not get Agent ID by hostname")
	t.Logf("Agent ID: %q", agentID)

	// We cannot search for `component.id` because at the moment of writing
	// this field is not mapped. There is an issue for that:
	// https://github.com/elastic/integrations/issues/6545
	// TODO: use runtime fields while the above issue is not resolved.

	docs = findESDocs(t, func() (estools.Documents, error) {
		return estools.GetLogsForAgentID(info.ESClient, agentID)
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

func findESDocs(t *testing.T, findFn func() (estools.Documents, error)) estools.Documents {
	var docs estools.Documents

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
