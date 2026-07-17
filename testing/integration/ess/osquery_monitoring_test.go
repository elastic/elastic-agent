// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
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
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
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
		Local: true, // requires Agent installation
		Sudo:  true, // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
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
		Develop:        true,
	}

	ctx, cancel := context.WithTimeout(runner.T().Context(), 3*time.Minute)
	defer cancel()

	require.NoError(runner.T(), fleettools.UpdateESOutputPreset(ctx, runner.info.KibanaClient, fleettools.DefaultFleetOutputID, fleettools.OutputPresetLatency))
	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.agentID = agentID
	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name
}

// TestLiveQueryRoutingNoSchedule is a regression test for
// https://github.com/elastic/elastic-agent/issues/15601.
//
// When an osquery integration has no scheduled queries the Fleet policy
// contains no "config.osquery" section. This bypassed the configuration
// translation logic to reorder the streams causing live-query result rows
// to be written to logs-osquery_manager.action.responses instead of
// logs-osquery_manager.result.
func (runner *OsqueryManagerRunner) TestLiveQueryRoutingNoSchedule() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	// Create a package with no schedule actions so only live queries can be processed.
	noScheduleFile := filepath.Join("testdata", "osquery_package_no_schedule.json")
	pkgResp, err := tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "osquery_manager",
		integration.PreinstalledPackages["osquery_manager"], noScheduleFile, uuid.Must(uuid.NewV4()).String(), runner.policyID)
	require.NoError(t, err, "failed to install no-schedule osquery package policy")
	packagePolicyID := pkgResp.Item.ID
	defer func() {
		if _, err := runner.info.KibanaClient.DeleteFleetPackage(t.Context(), packagePolicyID); err != nil {
			t.Logf("failed to delete no-schedule osquery package policy %s: %v", packagePolicyID, err)
		}
	}()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	// Wait for the osquery component to become healthy in OTel mode.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := runner.agentFixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)
		var foundHealthy bool
		for _, comp := range status.Components {
			if strings.HasPrefix(comp.ID, "osquery") &&
				comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.OtelRuntimeManager) &&
				comp.State == int(cproto.State_HEALTHY) {
				foundHealthy = true
				break
			}
		}
		assert.True(collect, foundHealthy, "expected a healthy OTel osquery component")
	}, 3*time.Minute, 5*time.Second, "osquery OTel component did not become healthy")

	// Dispatch a live query.
	liveQuery, err := submitOsqueryLiveQuery(ctx, runner.info.KibanaClient, agentStatus.Info.ID, "SELECT * FROM os_version;")
	require.NoError(t, err, "failed to submit live query")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := getOsqueryLiveQueryStatus(ctx, runner.info.KibanaClient, liveQuery.ActionID)
		require.NoError(collect, statusErr)
		assert.Equal(collect, "completed", status)
	}, 2*time.Minute, 5*time.Second, "live query did not complete")

	// Positive: result rows must appear in logs-osquery_manager.result*.
	// We require the "osquery" field so the assertion only matches actual result
	// rows, not the action-response summary (which also carries action_id but
	// has no osquery data).
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		query := genESQuery(agentStatus.Info.ID, [][]string{
			{"term", "action_id", liveQuery.QueryActionID},
			{"exists", "field", "osquery"},
		})
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-osquery_manager.result*", runner.info.ESClient)
		require.NoError(collect, err)
		require.NotEmpty(collect, res.Hits.Hits, "live-query result rows must appear in logs-osquery_manager.result*")
	}, 5*time.Minute, 10*time.Second, "live-query result rows not found in logs-osquery_manager.result*")

	// Negative: every document in action.responses for this action must be an
	// action-response summary (has action_response field). Before the fix, result
	// rows from the no-schedule component were misrouted here.
	misroutedQuery := genESQuery(agentStatus.Info.ID, [][]string{
		{"term", "action_id", liveQuery.QueryActionID},
	})
	misroutedRes, err := estools.PerformQueryForRawQuery(ctx, misroutedQuery, "logs-osquery_manager.action.responses*", runner.info.ESClient)
	require.NoError(t, err)
	for _, hit := range misroutedRes.Hits.Hits {
		_, hasActionResponse := hit.Source["action_response"]
		assert.True(t, hasActionResponse,
			"logs-osquery_manager.action.responses* must contain an action-response; found a misrouted result row: %v", hit.Source)
	}

}

func (runner *OsqueryManagerRunner) TestOtelAndProcessMode() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute*20)
	defer cancel()

	// Install a package with a scheduled query.
	packageFile := filepath.Join("testdata", "osquery_package.json")
	_, err := tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "osquery_manager",
		integration.PreinstalledPackages["osquery_manager"], packageFile, uuid.Must(uuid.NewV4()).String(), runner.policyID)
	require.NoError(t, err, "failed to install scheduled osquery package policy")

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	testStart := time.Now()

	// Validate process mode
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		processDoc = runner.validateOsqueryEvents(t, ctx, agentStatus.Info.ID, testStart)
	})

	// Switch to OTel runtime and validate the same data
	var otelDoc mapstr.M
	t.Run("otel", func(t *testing.T) {
		policyRevision := switchPolicyToOtelRuntime(ctx, t, runner.info.KibanaClient, runner.policyID, runner.policyName, runner.info.Namespace)

		// Wait for the agent to apply the new policy revision
		require.Eventually(t, tools.IsPolicyRevision(ctx, t, runner.info.KibanaClient, runner.agentID, policyRevision),
			5*time.Minute, time.Second)

		// Verify that an osquery component is running as a beats receiver.
		// The component may not appear immediately after the policy switch, so we
		// look for it inside the loop rather than capturing its ID up front.
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.agentFixture.ExecStatus(ctx)
			require.NoError(collect, statusErr)
			var foundReceiver bool
			for _, comp := range status.Components {
				if strings.HasPrefix(comp.ID, "osquery") &&
					comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.OtelRuntimeManager) {
					assert.Equal(collect, int(cproto.State_HEALTHY), comp.State,
						"expected osquery component to be healthy, got %s", cproto.State(comp.State))
					foundReceiver = true
					break
				}
			}
			assert.True(collect, foundReceiver, "expected an osquery component to be running as beats receiver")
		}, 2*time.Minute, 5*time.Second, "beat component should be running as beats receiver")

		otelDoc = runner.validateOsqueryEvents(t, ctx, agentStatus.Info.ID, testStart)
	})

	// Compare documents from process and otel modes have the same keys
	t.Run("compare", func(t *testing.T) {
		if processDoc == nil || otelDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		AssertMapstrKeysEqual(t, processDoc, otelDoc, RuntimeComparisonIgnoredFields, "expected osquery document keys to be equal between process and otel modes")
	})
}

// switchOsquerybeatToProcessRuntime updates the given policy to override the
// osquerybeat runtime to process and returns the new policy revision.
func switchOsquerybeatToProcessRuntime(ctx context.Context, t testing.TB, kibanaClient *kibana.Client, policyID, policyName, namespace string) int {
	t.Helper()
	updateReq := kibana.AgentPolicyUpdateRequest{
		Name:      policyName,
		Namespace: namespace,
		Overrides: map[string]interface{}{
			"agent": map[string]interface{}{
				"internal": map[string]interface{}{
					"runtime": map[string]interface{}{
						"osquerybeat": map[string]interface{}{
							"default": "process",
						},
					},
				},
			},
		},
	}
	policyResp, err := kibanaClient.UpdatePolicy(ctx, policyID, updateReq)
	require.NoError(t, err)
	return policyResp.Revision
}

func (runner *OsqueryManagerRunner) validateOsqueryEvents(t *testing.T, ctx context.Context, agentID string, since time.Time) mapstr.M {
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
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		query = genESQuery(agentID,
			[][]string{
				{"exists", "field", "osquery.physical_memory"},
			})
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")},
			},
		}
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-osquery_manager.result*", runner.info.ESClient)
		require.NoError(collect, err)
		require.NotEmpty(collect, res.Hits.Hits)
		doc = res.Hits.Hits[0].Source
	}, time.Minute*5, time.Second*10, "could not fetch events for osquery_manager")
	return doc
}

// osqueryLiveQuery identifies a submitted live query: ActionID is the parent
// action ID (used to poll status), QueryActionID is the per-query action ID
// (used to fetch results).
type osqueryLiveQuery struct {
	ActionID      string
	QueryActionID string
}

type osqueryLiveQueryCreateResponse struct {
	Data struct {
		ActionID string `json:"action_id"`
		Queries  []struct {
			ActionID string `json:"action_id"`
		} `json:"queries"`
	} `json:"data"`
}

// submitOsqueryLiveQuery submits a live query for the given agent via Kibana's
// osquery plugin (POST /api/osquery/live_queries), which creates a Fleet
// INPUT_ACTION with input_type "osquery" under the hood.
func submitOsqueryLiveQuery(ctx context.Context, client *kibana.Client, agentID, query string) (osqueryLiveQuery, error) {
	reqBody, err := json.Marshal(map[string]any{
		"agent_ids": []string{agentID},
		"query":     query,
	})
	if err != nil {
		return osqueryLiveQuery{}, fmt.Errorf("marshaling live query request: %w", err)
	}

	body, err := doOsqueryRequest(ctx, client, http.MethodPost, "/api/osquery/live_queries", bytes.NewReader(reqBody))
	if err != nil {
		return osqueryLiveQuery{}, fmt.Errorf("submitting osquery live query: %w", err)
	}

	var parsed osqueryLiveQueryCreateResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return osqueryLiveQuery{}, fmt.Errorf("unmarshaling osquery live query response: %w: %s", err, body)
	}
	if parsed.Data.ActionID == "" || len(parsed.Data.Queries) == 0 {
		return osqueryLiveQuery{}, fmt.Errorf("osquery live query response missing action id(s): %s", body)
	}

	return osqueryLiveQuery{
		ActionID:      parsed.Data.ActionID,
		QueryActionID: parsed.Data.Queries[0].ActionID,
	}, nil
}

type osqueryLiveQueryDetailsResponse struct {
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

// getOsqueryLiveQueryStatus fetches the status ("running" or "completed") of a
// previously submitted live query via GET /api/osquery/live_queries/{actionID}.
func getOsqueryLiveQueryStatus(ctx context.Context, client *kibana.Client, actionID string) (string, error) {
	body, err := doOsqueryRequest(ctx, client, http.MethodGet, "/api/osquery/live_queries/"+actionID, nil)
	if err != nil {
		return "", fmt.Errorf("fetching osquery live query details: %w", err)
	}

	var parsed osqueryLiveQueryDetailsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("unmarshaling osquery live query details response: %w: %s", err, body)
	}
	return parsed.Data.Status, nil
}

// osqueryAPIVersion is the versioned-route header required by the osquery
// plugin's public API. See
// x-pack/platform/plugins/shared/osquery/common/constants.ts (API_VERSIONS.public.v1)
// in the Kibana repository.
const osqueryAPIVersion = "2023-10-31"

func osqueryAPIHeaders() http.Header {
	h := http.Header{}
	h.Set("elastic-api-version", osqueryAPIVersion)
	return h
}

// doOsqueryRequest sends a request to the osquery plugin's API and returns the
// raw response body, after checking for a 200 status.
func doOsqueryRequest(ctx context.Context, client *kibana.Client, method, path string, reqBody io.Reader) ([]byte, error) {
	resp, err := client.SendWithContext(ctx, method, path, nil, osqueryAPIHeaders(), reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
