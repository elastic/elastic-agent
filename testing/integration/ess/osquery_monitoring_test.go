// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/component"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/testing/integration"
)

type OsqueryManagerRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost     string
	agentID    string
	policyID   string
	policyName string
}

func TestOsqueryManager(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	suite.Run(t, &OsqueryManagerRunner{info: info})
}

func (runner *OsqueryManagerRunner) SetupSuite() {
	fixture, err := define.NewFixtureFromLocalBuild(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   runner.info.Namespace,
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.agentID = agentID
	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name

	packageFile := filepath.Join("testdata", "osquery_package.json")
	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "osquery_manager",
		integration.PreinstalledPackages["osquery_manager"], packageFile, uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

func (runner *OsqueryManagerRunner) switchToOtelRuntime(ctx context.Context) int {
	updateReq := kibana.AgentPolicyUpdateRequest{
		Name:      runner.policyName,
		Namespace: runner.info.Namespace,
		Overrides: map[string]interface{}{
			"agent": map[string]interface{}{
				"internal": map[string]interface{}{
					"runtime": map[string]interface{}{
						"default": "otel",
					},
				},
			},
		},
	}
	policyResp, err := runner.info.KibanaClient.UpdatePolicy(ctx, runner.policyID, updateReq)
	require.NoError(runner.T(), err)
	return policyResp.Revision
}

func (runner *OsqueryManagerRunner) validateOsqueryEvents(ctx context.Context, agentID string, since time.Time) mapstr.M {
	t := runner.T()

	now := time.Now()
	var query map[string]any
	var doc mapstr.M
	defer func() {
		if t.Failed() {
			bs, err := json.Marshal(query)
			if err != nil {
				t.Errorf("executed at %s: %v",
					now.Format(time.RFC3339Nano), query)
				return
			}
			t.Errorf("executed at %s: query: %s",
				now.Format(time.RFC3339Nano), string(bs))
		}
	}()

	t.Logf("starting to query ES for osquery events at %s", now.Format(time.RFC3339Nano))
	require.Eventually(t, func() bool {
		query = genESQuery(agentID,
			[][]string{
				{"exists", "field", "osquery.physical_memory"},
			})
		if !since.IsZero() {
			query["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = map[string]any{
				"range": map[string]any{
					"@timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")},
				},
			}
		}
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-osquery_manager.result*", runner.info.ESClient)
		require.NoError(t, err)
		if res.Hits.Total.Value < 1 {
			return false
		}
		doc = res.Hits.Hits[0].Source
		return true
	}, time.Minute*15, time.Second*10, "could not fetch events for osquery_manager")
	return doc
}

func (runner *OsqueryManagerRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	// Validate process mode
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		processDoc = runner.validateOsqueryEvents(ctx, agentStatus.Info.ID, time.Time{})
	})

	// Switch to OTel runtime and validate the same data
	var otelDoc mapstr.M
	t.Run("otel", func(t *testing.T) {
		otelSince := time.Now()
		policyRevision := runner.switchToOtelRuntime(ctx)

		// Wait for the agent to apply the new policy revision
		require.Eventually(t, tools.IsPolicyRevision(ctx, t, runner.info.KibanaClient, runner.agentID, policyRevision),
			5*time.Minute, time.Second)

		// Verify the component is running as a beats receiver
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.agentFixture.ExecStatus(ctx)
			require.NoError(collect, statusErr)
			var hasReceiver bool
			for _, comp := range status.Components {
				if comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.OtelRuntimeManager) {
					hasReceiver = true
					break
				}
			}
			assert.True(collect, hasReceiver, "expected a component running as beats receiver")
		}, 2*time.Minute, 5*time.Second, "component should be running as beats receiver")

		otelDoc = runner.validateOsqueryEvents(ctx, agentStatus.Info.ID, otelSince)
	})

	// Compare documents from process and otel modes have the same keys
	t.Run("compare", func(t *testing.T) {
		if processDoc == nil || otelDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		AssertMapstrKeysEqual(t, processDoc, otelDoc, RuntimeComparisonIgnoredFields, "expected osquery document keys to be equal between process and otel modes")
	})
}
