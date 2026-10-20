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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestAgentInfoInEventsStandalone(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	esHost, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esAPIKey, err := getDecodedApiKey(createESApiKey(t, info.ESClient))
	require.NoError(t, err, "error decoding the elasticsearch api key")

	for _, runtime := range allRuntimes {
		t.Run(runtime, func(t *testing.T) {
			runAgentInfoInEventsStandalone(t, info, runtime, esHost, esAPIKey)
		})
	}
}

func runAgentInfoInEventsStandalone(t *testing.T, info *define.Info, runtime, esHost, esAPIKey string) {
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	integrationTags := []string{"integration-a"}
	agentTags := []string{"standalone-a", "standalone-b"}
	newTags := []string{"standalone-c"}

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "failed creating agent fixture")

	logFilePath := filepath.Join(createTempDir(t), "flog.log")
	integration.GenerateLogFile(t, logFilePath, time.Second/2, 0)

	var status atesting.AgentStatusOutput
	t.Run("agent starts with tags", func(t *testing.T) {
		err := updateAgentTags(ctx, agentFixture, esHost, esAPIKey, logFilePath, runtime, integrationTags, agentTags)
		require.NoError(t, err, "error configuring the agent tags")
		installOutput, err := agentFixture.Install(ctx, &atesting.InstallOpts{NonInteractive: true, Force: true})
		require.NoErrorf(t, err, "error installing agent, output:\n%s", installOutput)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			err := agentFixture.IsHealthy(ctx)
			require.NoError(c, err)
		}, 2*time.Minute, time.Second, "agent did not become healthy")

		status, err = agentFixture.ExecStatus(ctx)
		require.NoError(t, err, "could not get the agent status")
		expectedTags := slices.Concat(integrationTags, agentTags)
		requireAgentInfoInEvents(t, ctx, info, status, logFilePath, expectedTags)
	})

	t.Run("agent tags are updated", func(t *testing.T) {
		err := updateAgentTags(ctx, agentFixture, esHost, esAPIKey, logFilePath, runtime, integrationTags, newTags)
		require.NoError(t, err, "error updating the agent tags")
		expectedTags := slices.Concat(integrationTags, newTags)
		requireAgentInfoInEvents(t, ctx, info, status, logFilePath, expectedTags)
	})

	t.Run("agent tags survive a restart", func(t *testing.T) {
		err := agentFixture.ExecRestart(ctx)
		require.NoError(t, err, "could not restart the agent")
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			err := agentFixture.IsHealthy(ctx)
			require.NoError(c, err)
		}, 2*time.Minute, time.Second, "agent did not become healthy after the restart")

		restarted := time.Now()
		expectedTags := slices.Concat(integrationTags, newTags)
		requireAgentInfoInEventsAfter(t, ctx, info, status, logFilePath, expectedTags, restarted)
	})
}

func TestAgentInfoInEventsFleetManaged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, runtime := range allRuntimes {
		t.Run(runtime, func(t *testing.T) {
			runAgentInfoInEventsFleetManaged(t, info, runtime)
		})
	}
}

func runAgentInfoInEventsFleetManaged(t *testing.T, info *define.Info, runtime string) {
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()

	integrationTags := []string{"integration-a"}
	agentTags := []string{"installed-a", "installed-b"}
	newTags := []string{"installed-c"}

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "failed creating agent fixture")

	logFilePath := filepath.Join(createTempDir(t), "flog.log")
	integration.GenerateLogFile(t, logFilePath, time.Second/2, 0)
	enrollmentToken := createAgentInfoPolicy(t, ctx, info, agentFixture, runtime, logFilePath, integrationTags)

	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	var status atesting.AgentStatusOutput
	t.Run("agent starts with tags", func(t *testing.T) {
		installOutput, err := agentFixture.Install(ctx, &atesting.InstallOpts{
			NonInteractive: true,
			Force:          true,
			EnrollOpts: atesting.EnrollOpts{
				URL:             fleetServerURL,
				EnrollmentToken: enrollmentToken,
				Tags:            agentTags,
			},
		})
		require.NoErrorf(t, err, "error installing agent, output:\n%s", installOutput)
		require.Eventuallyf(t, func() bool {
			return waitForAgentAndFleetHealthy(ctx, t, agentFixture)
		}, 2*time.Minute, time.Second, "agent never became healthy or connected to Fleet")

		status, err = agentFixture.ExecStatus(ctx)
		require.NoError(t, err, "could not get the agent status")
		expectedTags := slices.Concat(integrationTags, agentTags)
		requireAgentInfoInEvents(t, ctx, info, status, logFilePath, expectedTags)
	})

	t.Run("agent tags are updated", func(t *testing.T) {
		// Fleet Server sends a tags-only change at the next check-in, which can take up
		// to the long poll timeout (about 5 minutes).
		err := updateAgentTagsFleet(ctx, info, status.Info.ID, newTags)
		require.NoError(t, err, "error updating the agent tags")
		expectedTags := slices.Concat(integrationTags, newTags)
		requireAgentInfoInEvents(t, ctx, info, status, logFilePath, expectedTags)
	})

	t.Run("agent tags survive a restart", func(t *testing.T) {
		err := agentFixture.ExecRestart(ctx)
		require.NoError(t, err, "could not restart the agent")
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			err := agentFixture.IsHealthy(ctx)
			require.NoError(c, err)
		}, 2*time.Minute, time.Second, "agent did not become healthy after the restart")

		restarted := time.Now()
		expectedTags := slices.Concat(integrationTags, newTags)
		requireAgentInfoInEventsAfter(t, ctx, info, status, logFilePath, expectedTags, restarted)
	})
}

func TestAgentInfoInEventsFleetManagedContainer(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Container,
		Stack: &define.Stack{},
		Local: true,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, runtime := range allRuntimes {
		t.Run(runtime, func(t *testing.T) {
			runAgentInfoInEventsFleetManagedContainer(t, info, runtime)
		})
	}
}

func runAgentInfoInEventsFleetManagedContainer(t *testing.T, info *define.Info, runtime string) {
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()

	integrationTags := []string{"integration-a"}
	agentTags := []string{"container-a", "container-b"}
	newTags := []string{"container-c"}

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "failed creating agent fixture")
	err = agentFixture.Prepare(ctx)
	require.NoError(t, err, "failed preparing agent fixture")

	logFilePath := filepath.Join(createTempDir(t), "flog.log")
	integration.GenerateLogFile(t, logFilePath, time.Second/2, 0)
	enrollmentToken := createAgentInfoPolicy(t, ctx, info, agentFixture, runtime, logFilePath, integrationTags)

	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	env := []string{
		"FLEET_ENROLL=1",
		"FLEET_URL=" + fleetServerURL,
		"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
		"ELASTIC_AGENT_TAGS=" + strings.Join(agentTags, ","),
		"STATE_PATH=" + agentFixture.WorkDir(),
	}
	// The command belongs to the whole test: its cleanup stops the agent when the test ends.
	cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container"}, env)

	var status atesting.AgentStatusOutput
	t.Run("agent starts with tags", func(t *testing.T) {
		err := cmd.Start()
		require.NoError(t, err, "failed starting container agent")
		require.Eventuallyf(t, func() bool {
			return agentFixture.IsHealthy(ctx, atesting.WithCmdOptions(withEnv(env))) == nil
		}, 2*time.Minute, time.Second,
			"container agent did not become healthy; output:\n%s", agentOutput.String())

		status, err = agentFixture.ExecStatus(ctx, atesting.WithCmdOptions(withEnv(env)))
		require.NoError(t, err, "could not get the agent status")
		expectedTags := slices.Concat(integrationTags, agentTags)
		requireAgentInfoInEvents(t, ctx, info, status, logFilePath, expectedTags)
	})

	t.Run("agent tags are updated", func(t *testing.T) {
		// Fleet Server sends a tags-only change at the next check-in, which can take up
		// to the long poll timeout (about 5 minutes).
		err := updateAgentTagsFleet(ctx, info, status.Info.ID, newTags)
		require.NoError(t, err, "error updating the agent tags")
		expectedTags := slices.Concat(integrationTags, newTags)
		requireAgentInfoInEvents(t, ctx, info, status, logFilePath, expectedTags)
	})

	t.Run("agent tags survive a restart", func(t *testing.T) {
		err := agentFixture.ExecRestart(ctx, withEnv(env))
		require.NoError(t, err, "could not restart the agent")
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			err := agentFixture.IsHealthy(ctx, atesting.WithCmdOptions(withEnv(env)))
			require.NoError(c, err)
		}, 2*time.Minute, time.Second, "agent did not become healthy after the restart")

		restarted := time.Now()
		expectedTags := slices.Concat(integrationTags, newTags)
		requireAgentInfoInEventsAfter(t, ctx, info, status, logFilePath, expectedTags, restarted)
	})
}

func createAgentInfoPolicy(t *testing.T, ctx context.Context, info *define.Info, agentFixture *atesting.Fixture, runtime, logFilePath string, integrationTags []string) string {
	t.Helper()
	// include_tags_in_events is disabled by default, so the policy must enable it.
	enabledIncludeTagsInEvents := map[string]any{
		"agent": map[string]any{
			"monitoring": map[string]any{
				"enabled": false,
			},
			"features": map[string]any{
				"include_tags_in_events": map[string]any{
					"enabled": true,
				},
			},
			"internal": map[string]any{
				"runtime": map[string]any{
					"default": runtime,
					"filebeat": map[string]any{
						"default": runtime,
					},
				},
			},
		},
	}
	policyName := fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String())
	policyID, enrollmentToken := createPolicyWithOverride(t, ctx, agentFixture, info, policyName, "", enabledIncludeTagsInEvents)
	addLogIntegration(t, info, policyID, logFilePath, integrationTags...)
	return enrollmentToken
}

func updateAgentTags(ctx context.Context, agentFixture *atesting.Fixture, esHost, esAPIKey, logFilePath, runtime string, integrationTags, tags []string) error {
	// include_tags_in_events is disabled by default, so the configuration must enable it.
	configTemplate := `
outputs:
  default:
    type: elasticsearch
    hosts:
      - %[1]s
    api_key: "%[2]s"
    preset: latency
inputs:
  - type: filestream
    id: agent-info-input-id
    streams:
      - id: agent-info-filestream-stream-id
        data_stream:
          dataset: generic
        paths:
          - %[3]s
        tags: [%[4]s]
agent:
    monitoring.enabled: false
    internal.runtime.filebeat.default: %[5]s
    features.include_tags_in_events.enabled: true
    tags: [%[6]s]
`
	cfg := fmt.Sprintf(configTemplate,
		esHost,
		esAPIKey,
		logFilePath,
		strings.Join(integrationTags, ", "),
		runtime,
		strings.Join(tags, ", "))
	if err := agentFixture.Configure(ctx, []byte(cfg)); err != nil {
		return fmt.Errorf("configure agent tags: %w", err)
	}
	return nil
}

func updateAgentTagsFleet(ctx context.Context, info *define.Info, agentID string, tags []string) error {
	body, err := json.Marshal(map[string]any{"tags": tags})
	if err != nil {
		return fmt.Errorf("marshal agent tags: %w", err)
	}

	resp, err := info.KibanaClient.SendWithContext(ctx, http.MethodPut, "/api/fleet/agents/"+agentID, nil, nil, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("update agent tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("update agent tags: status %d, read body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("update agent tags: status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

func requireAgentInfoInEvents(t *testing.T, ctx context.Context, info *define.Info, status atesting.AgentStatusOutput, logFilePath string, tags []string) {
	t.Helper()
	requireAgentInfoInEventsAfter(t, ctx, info, status, logFilePath, tags, time.Time{})
}

func requireAgentInfoInEventsAfter(t *testing.T, ctx context.Context, info *define.Info, status atesting.AgentStatusOutput, logFilePath string, tags []string, after time.Time) {
	t.Helper()
	filters := []map[string]any{
		{"term": map[string]any{"agent.id": status.Info.ID}},
		{"term": map[string]any{"elastic_agent.id": status.Info.ID}},
		{"term": map[string]any{"elastic_agent.version": status.Info.Version}},
		{"term": map[string]any{"elastic_agent.snapshot": strconv.FormatBool(status.Info.Snapshot)}},
		{"term": map[string]any{"log.file.path": logFilePath}},
	}
	for _, tag := range tags {
		filters = append(filters, map[string]any{"term": map[string]any{"tags": tag}})
	}
	if !after.IsZero() {
		filters = append(filters, map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gt": after.UTC().Format(time.RFC3339Nano)}}})
	}

	query := map[string]any{"query": map[string]any{"bool": map[string]any{"filter": filters}}}
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-*", info.ESClient)
		require.NoError(c, err)
		assert.Positive(c, res.Hits.Total.Value, "no document has all the expected agent info fields")
	}, 10*time.Minute, 5*time.Second, "no event of %s with the agent info %v", logFilePath, filters)
}
