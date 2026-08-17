// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"encoding/json"
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

type AuditDRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost     string
	agentID    string
	policyID   string
	policyName string
}

func TestAuditdCorrectBinaries(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			// Skipped on Debian, see https://github.com/elastic/elastic-agent/issues/7813
			{Type: define.Linux, Distro: "ubuntu"},
			{Type: define.Linux, Distro: "rhel"},
		},
	})

	suite.Run(t, &AuditDRunner{info: info})
}

func (runner *AuditDRunner) SetupSuite() {
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

	ctx, cancel := context.WithTimeout(runner.T().Context(), 3*time.Minute)
	defer cancel()

	require.NoError(runner.T(), fleettools.UpdateESOutputPreset(ctx, runner.info.KibanaClient, fleettools.DefaultFleetOutputID, fleettools.OutputPresetLatency))
	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.agentID = agentID
	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name

	packageFile := filepath.Join("testdata", "auditd_package.json")
	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "auditd_manager",
		integration.PreinstalledPackages["auditd_manager"], packageFile, uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

// validateAuditdEvents waits for an auditd execve event for the elastic-agent
// binary to appear in ES from the given agent since the given time. The
// elastic-agent binary is exec'd on every ExecStatus call, so calling
// ExecStatus inside the retry loop guarantees events are generated even if
// audit rules became active after the health-check loop exited. Filtering by
// process.name ensures we compare apples to apples: both OTel and process mode
// will see events from the same binary, which always runs inside the test's
// SSH login session (auid set, kernel audit session populated).
func (runner *AuditDRunner) validateAuditdEvents(t *testing.T, ctx context.Context, agentID string, since time.Time) mapstr.M {
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

	requiredFields := [][]string{
		{"term", "tags", "elastic-agent-test"},
		{"term", "process.name", "elastic-agent"},
	}

	t.Logf("starting to query ES for auditd events at %s", now.Format(time.RFC3339Nano))
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		// Exec elastic-agent on every retry tick to keep generating tagged audit events.
		// This covers the window between audit rules becoming active and the first ES hit.
		_, err := runner.agentFixture.ExecStatus(ctx)
		if err != nil {
			t.Logf("error getting agent status: %v", err)
		}

		query = genESQuery(agentID, requiredFields)
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")},
			},
		}
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-auditd_manager.auditd*", runner.info.ESClient)
		require.NoError(collect, err)
		require.NotEmpty(collect, res.Hits.Hits)
		doc = res.Hits.Hits[0].Source
	}, time.Minute*10, time.Second*10, "could not fetch events for auditd_manager")
	return doc
}

func (runner *AuditDRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	testStart := time.Now()

	// The package installed for this test, defined in testing/integration/ess/testdata/auditd_package.json configures
	// the auditd input to track execve events from the test binary itself. The test shells out to elastic-agent each
	// time it collects the status, so we're guaranteed to have events in the monitored time window.

	// Validate OTel mode (the default for auditbeat).
	var otelDoc mapstr.M
	t.Run("otel", func(t *testing.T) {
		// Verify that an audit/auditd component is running as a beats receiver.
		// The component may not appear immediately after startup, so we look for
		// it inside the loop rather than capturing its ID up front.
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.agentFixture.ExecStatus(ctx)
			require.NoError(collect, statusErr)
			var foundReceiver bool
			for _, comp := range status.Components {
				if strings.HasPrefix(comp.ID, "audit/auditd") &&
					comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.OtelRuntimeManager) {
					compStateProto := cproto.State(comp.State) //nolint:gosec // guaranteed to be valid
					assert.Equal(collect, cproto.State_HEALTHY, compStateProto,
						"expected audit/auditd component to be healthy, got %s", compStateProto)
					foundReceiver = true
					break
				}
			}
			assert.True(collect, foundReceiver, "expected an audit/auditd component to be running as beats receiver")
		}, 2*time.Minute, 5*time.Second, "beat component should be running as beats receiver")

		otelDoc = runner.validateAuditdEvents(t, ctx, agentStatus.Info.ID, testStart)
	})

	// Switch to process runtime and validate the same data.
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		processSince := time.Now()
		policyRevision := switchAuditbeatToProcessRuntime(ctx, t, runner.info.KibanaClient, runner.policyID, runner.policyName, runner.info.Namespace)

		// Wait for the agent to apply the new policy revision.
		require.Eventually(t, tools.IsPolicyRevision(ctx, t, runner.info.KibanaClient, runner.agentID, policyRevision),
			5*time.Minute, time.Second)

		// Verify that the audit/auditd component has switched to process mode.
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.agentFixture.ExecStatus(ctx)
			require.NoError(collect, statusErr)
			var foundProcess bool
			for _, comp := range status.Components {
				if strings.HasPrefix(comp.ID, "audit/auditd") &&
					comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.ProcessRuntimeManager) {
					compStateProto := cproto.State(comp.State) //nolint:gosec // guaranteed to be valid
					assert.Equal(collect, cproto.State_HEALTHY, compStateProto,
						"expected audit/auditd component to be healthy, got %s", compStateProto)
					foundProcess = true
					break
				}
			}
			assert.True(collect, foundProcess, "expected an audit/auditd component to be running as a process")
		}, 2*time.Minute, 5*time.Second, "beat component should be running as a process")

		processDoc = runner.validateAuditdEvents(t, ctx, agentStatus.Info.ID, processSince)
	})

	// Compare documents from otel and process modes have the same keys.
	// auditd.data fields are excluded because their subkeys can vary across
	// individual execve events depending on kernel version and PAM configuration.
	t.Run("compare", func(t *testing.T) {
		if otelDoc == nil || processDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		ignoredFields := append(RuntimeComparisonIgnoredFields, "auditd.data")
		AssertMapstrKeysEqual(t, otelDoc, processDoc, ignoredFields, "expected auditd document keys to be equal between otel and process modes")
	})
}

// switchAuditbeatToProcessRuntime updates the given policy to override the
// auditbeat runtime to process and returns the new policy revision.
func switchAuditbeatToProcessRuntime(ctx context.Context, t testing.TB, kibanaClient *kibana.Client, policyID, policyName, namespace string) int {
	t.Helper()
	updateReq := kibana.AgentPolicyUpdateRequest{
		Name:      policyName,
		Namespace: namespace,
		Overrides: map[string]interface{}{
			"agent": map[string]interface{}{
				"internal": map[string]interface{}{
					"runtime": map[string]interface{}{
						"auditbeat": map[string]interface{}{
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
