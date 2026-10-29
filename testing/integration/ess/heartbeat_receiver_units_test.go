// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

const (
	// heartbeatReceiverMonitors is the number of monitors the receiver runs. It
	// is large enough that recreating the receiver for every change would show.
	heartbeatReceiverMonitors = 1000

	heartbeatReceiverComponentID = "synthetics/http-default"
	heartbeatMonitorSchedule     = "@every 10s"
)

// collectorReloadMessages are the collector log messages that show it applied a
// new configuration, or started the Heartbeat receiver.
var collectorReloadMessages = []string{
	"Config updated",
	"Everything is ready. Begin running and processing data",
	"starting heartbeat receiver",
}

// TestHeartbeatReceiverMonitorChanges checks that monitor changes reach the
// Heartbeat receiver over the control protocol: the collector keeps its
// configuration and its receiver, and the status of the changed monitors
// follows the changes.
func TestHeartbeatReceiverMonitorChanges(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(20*time.Minute))
	defer cancel()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	esURL := integration.StartMockES(t, 0, 0, 0, 0)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	require.NoError(t, fixture.Prepare(ctx))

	monitors := make(map[string]string, heartbeatReceiverMonitors)
	for i := range heartbeatReceiverMonitors {
		monitors[heartbeatMonitorID(i)] = heartbeatMonitorSchedule
	}
	configure := func() {
		t.Helper()
		policy, err := heartbeatReceiverPolicy(esURL.String(), target.URL, monitors)
		require.NoError(t, err)
		require.NoError(t, fixture.Configure(ctx, policy))
	}
	configure()

	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err)
	output := strings.Builder{}
	cmd.Stdout = &output
	cmd.Stderr = &output
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("Elastic Agent output:\n%s", output.String())
		}
	})

	logsDir := filepath.Join(fixture.WorkDir(), "data", "elastic-agent-*", "logs")

	t.Logf("waiting for %d monitors to be healthy", heartbeatReceiverMonitors)
	start := time.Now()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		units := heartbeatReceiverUnits(ctx, c, fixture)
		assert.Len(c, units, len(monitors))
		for id := range monitors {
			assertMonitorUnit(c, units, id, cproto.State_HEALTHY, "")
		}
	}, 10*time.Minute, 5*time.Second, "monitors did not become healthy")
	t.Logf("monitors healthy after %s", time.Since(start))

	before := countCollectorLogMessages(t, logsDir)
	for _, msg := range collectorReloadMessages[1:] {
		require.Positivef(t, before[msg], "the collector never logged %q, the logs can't show a reload", msg)
	}

	// Break one monitor, remove another and add a new one.
	broken, removed, added := heartbeatMonitorID(0), heartbeatMonitorID(1), heartbeatMonitorID(heartbeatReceiverMonitors)
	monitors[broken] = "not a schedule"
	delete(monitors, removed)
	monitors[added] = heartbeatMonitorSchedule
	start = time.Now()
	configure()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		units := heartbeatReceiverUnits(ctx, c, fixture)
		assert.Len(c, units, len(monitors))
		assert.NotContains(c, units, heartbeatUnitID(removed), "the removed monitor should be gone")
		assertMonitorUnit(c, units, broken, cproto.State_FAILED, "schedule")
		assertMonitorUnit(c, units, added, cproto.State_HEALTHY, "")
	}, 3*time.Minute, time.Second, "monitor status did not follow the changes")
	t.Logf("monitor status followed the changes after %s", time.Since(start))

	// Fix the broken monitor.
	monitors[broken] = heartbeatMonitorSchedule
	start = time.Now()
	configure()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		units := heartbeatReceiverUnits(ctx, c, fixture)
		for id := range monitors {
			assertMonitorUnit(c, units, id, cproto.State_HEALTHY, "")
		}
	}, 3*time.Minute, time.Second, "the fixed monitor did not become healthy")
	t.Logf("the fixed monitor was healthy after %s", time.Since(start))

	assert.Equal(t, before, countCollectorLogMessages(t, logsDir),
		"the collector should neither reload its configuration nor recreate the receiver for monitor changes")
}

func heartbeatMonitorID(i int) string {
	return fmt.Sprintf("monitor-%04d", i)
}

// heartbeatUnitID returns the ID of the input unit for a monitor.
func heartbeatUnitID(monitorID string) string {
	return heartbeatReceiverComponentID + "-synthetics/http-" + monitorID
}

// heartbeatReceiverPolicy returns a standalone policy running a synthetics HTTP
// monitor for each schedule in monitors, all in the Heartbeat receiver. Each
// monitor is an input with one stream, shaped like the inputs Fleet sends for
// Synthetics monitors.
func heartbeatReceiverPolicy(esURL string, targetURL string, monitors map[string]string) ([]byte, error) {
	inputs := make([]map[string]any, 0, len(monitors))
	for id, schedule := range monitors {
		inputs = append(inputs, map[string]any{
			"id":         "synthetics/http-" + id,
			"type":       "synthetics/http",
			"use_output": "default",
			"data_stream": map[string]any{
				"namespace": "default",
			},
			"streams": []map[string]any{{
				"id":       "http-" + id,
				"name":     id,
				"type":     "http",
				"enabled":  true,
				"urls":     []string{targetURL},
				"schedule": schedule,
				"data_stream": map[string]any{
					"dataset": "http",
					"type":    "synthetics",
				},
			}},
		})
	}
	return yaml.Marshal(map[string]any{
		"outputs": map[string]any{
			"default": map[string]any{
				"type":     "elasticsearch",
				"hosts":    []string{esURL},
				"protocol": "http",
				"preset":   "latency",
			},
		},
		"inputs": inputs,
		"agent": map[string]any{
			"monitoring.enabled":                 false,
			"internal.runtime.heartbeat.default": "otel",
			"grpc.port":                          0,
		},
	})
}

type monitorUnitState struct {
	state   int
	message string
	errors  []string
}

// heartbeatReceiverUnits returns the state of the Heartbeat receiver's input
// units, by unit ID.
func heartbeatReceiverUnits(ctx context.Context, c *assert.CollectT, fixture *atesting.Fixture) map[string]monitorUnitState {
	status, err := fixture.ExecStatus(ctx)
	if !assert.NoError(c, err) {
		return nil
	}
	units := map[string]monitorUnitState{}
	for _, comp := range status.Components {
		if comp.ID != heartbeatReceiverComponentID {
			continue
		}
		for _, unit := range comp.Units {
			if unit.UnitType != int(cproto.UnitType_INPUT) {
				continue
			}
			state := monitorUnitState{state: unit.State, message: unit.Message}
			for _, stream := range unit.Payload.Streams {
				state.errors = append(state.errors, stream.Error)
			}
			units[unit.UnitID] = state
		}
	}
	return units
}

// assertMonitorUnit asserts the state of a monitor's unit, and that one of its
// streams has an error containing errorSnippet, if it isn't empty.
func assertMonitorUnit(c *assert.CollectT, units map[string]monitorUnitState, monitorID string, state cproto.State, errorSnippet string) {
	unit, ok := units[heartbeatUnitID(monitorID)]
	if !assert.Truef(c, ok, "no unit for monitor %s", monitorID) {
		return
	}
	assert.Equalf(c, int(state), unit.state, "unexpected state for monitor %s: %s", monitorID, unit.message)
	if errorSnippet != "" {
		assert.Truef(c, strings.Contains(strings.Join(unit.errors, "\n"), errorSnippet),
			"no stream error containing %q for monitor %s: %v", errorSnippet, monitorID, unit.errors)
	}
}

// countCollectorLogMessages counts the lines in the collector logs containing
// each of collectorReloadMessages.
func countCollectorLogMessages(t *testing.T, logsDir string) map[string]int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(logsDir, "elastic-otel-collector-*.ndjson"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "no collector log files in %s", logsDir)

	counts := make(map[string]int, len(collectorReloadMessages))
	for _, file := range files {
		f, err := os.Open(file)
		require.NoError(t, err)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			for _, msg := range collectorReloadMessages {
				if strings.Contains(scanner.Text(), msg) {
					counts[msg]++
				}
			}
		}
		require.NoError(t, scanner.Err())
		require.NoError(t, f.Close())
	}
	return counts
}
