// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

var eventLogConfig = `
outputs:
  default:
    type: elasticsearch
    hosts:
      - %[1]s
    protocol: http
    preset: latency
inputs:
  - type: filestream
    id: your-input-id
    log_level: debug
    streams:
      - id: your-filestream-stream-id
        data_stream:
          dataset: generic
        paths:
          - %[2]s
agent:
    logging.level: debug
    monitoring.enabled: false
    internal.runtime.filebeat.default: %[3]s
    grpc:
        address: localhost
        port: 7001
`

const (
	runtimeProcess = "process"
	runtimeOtel    = "otel"
)

var allRuntimes = []string{runtimeProcess, runtimeOtel}

func TestEventLogFile(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
	})

	for _, runtime := range allRuntimes {
		t.Run(runtime, func(t *testing.T) {
			runEventLogFile(t, runtime)
		})
	}
}

func runEventLogFile(t *testing.T, runtime string) {
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	esURL := integration.StartMockES(t, 0, 0, 0, 0)

	logFilepath := path.Join(t.TempDir(), "flog.log")
	integration.GenerateLogFile(t, logFilepath, time.Millisecond*100, 20)

	cfg := fmt.Sprintf(eventLogConfig, esURL.String(), logFilepath, runtime)

	if err := agentFixture.Prepare(ctx); err != nil {
		t.Fatalf("cannot prepare Elastic-Agent fixture: %s", err)
	}

	if err := agentFixture.Configure(ctx, []byte(cfg)); err != nil {
		t.Fatalf("cannot configure Elastic-Agent fixture: %s", err)
	}

	cmd, err := agentFixture.PrepareAgentCommand(ctx, nil)
	if err != nil {
		t.Fatalf("cannot prepare Elastic-Agent command: %s", err)
	}

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start Elastic-Agent: %s", err)
	}

	t.Cleanup(func() {
		_ = cmd.Wait()
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	requireEventLogFileExistsWithData(t, agentFixture, "Publish event: ")
	requireNoCopyProcessorError(t, agentFixture)

	logsDirGlob := filepath.Join(agentFixture.WorkDir(), "data", "elastic-agent-*", "logs")
	requireLogFileLayoutForRuntime(t, logsDirGlob, runtime)
	requireNoEventLeakage(t, logsDirGlob)

	// Diagnostics command behavior is tested elsewhere, here we only
	// check that log filenames are included/excluded correctly.
	expectedLogFiles, expectedEventLogFiles := getLogFilenames(t, logsDirGlob)
	require.NotEmpty(t, expectedLogFiles)
	require.NotEmpty(t, expectedEventLogFiles)

	collectDiagnosticsAndVeriflyLogs(
		t,
		ctx,
		agentFixture,
		[]string{"diagnostics", "collect"},
		append(expectedLogFiles, expectedEventLogFiles...))

	collectDiagnosticsAndVeriflyLogs(
		t,
		ctx,
		agentFixture,
		[]string{"diagnostics", "collect", "--exclude-events"},
		expectedLogFiles)
}

var fleetManagedAgentConfig = `
fleet:
  enabled: true
agent:
  grpc:
    address: localhost
    port: 7002
`

func TestEventLogOutputConfiguredViaFleet(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, runtime := range allRuntimes {
		t.Run(runtime, func(t *testing.T) {
			runEventLogOutputConfiguredViaFleet(t, info, runtime)
		})
	}
}

func runEventLogOutputConfiguredViaFleet(t *testing.T, info *define.Info, runtime string) {
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	_, outputID := createMockESOutput(t, info, 0, 0, 100, 0)
	policyName := fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String())
	policyID, enrollmentAPIKey := createPolicyWithOverride(
		t,
		ctx,
		agentFixture,
		info,
		policyName,
		outputID,
		map[string]any{
			"agent": map[string]any{
				"logging": map[string]any{
					"level": "debug",
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
		},
	)

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	enrollArgs := []string{
		"enroll",
		"--force",
		"--skip-daemon-reload",
		"--url",
		fleetURL,
		"--enrollment-token",
		enrollmentAPIKey,
	}

	logFilePath := filepath.Join(t.TempDir(), "flog.log")
	addLogIntegration(t, info, policyID, logFilePath)
	integration.GenerateLogFile(t, logFilePath, time.Second/2, 100)

	enrollCmd, err := agentFixture.PrepareAgentCommand(ctx, enrollArgs)
	if err != nil {
		t.Fatalf("could not prepare enroll command: %s", err)
	}
	if out, err := enrollCmd.CombinedOutput(); err != nil {
		t.Fatalf("error enrolling elastic-agent: %s\nOutput:\n%s", err, string(out))
	}

	err = agentFixture.Configure(ctx, []byte(fleetManagedAgentConfig))
	require.NoError(t, err)

	runAgentCMD, agentOutput := prepareAgentCMD(t, ctx, agentFixture, nil, nil)
	if err := runAgentCMD.Start(); err != nil {
		t.Fatalf("could not start elastic-agent: %s", err)
	}

	t.Cleanup(func() {
		if t.Failed() {
			t.Errorf("elastic-agent output:\n%s", agentOutput)
		}
	})

	require.Eventually(t, func() bool {
		return waitForAgentAndFleetHealthy(ctx, t, agentFixture)
	}, 2*time.Minute, time.Second, "elastic-agent did not report healthy")

	// Ensure the event logs are going to the events log file by default.
	requireEventLogFileExistsWithData(t, agentFixture, "Publish event:")

	// Add a policy overwrite to change the events output to stderr.
	err = applyEventLogStderrPolicy(ctx, info, policyName, policyID, runtime)
	require.NoError(t, err)

	// Wait until the agent has applied the policy change.
	require.Eventually(t, func() bool {
		inspect, inspectErr := agentFixture.ExecInspect(ctx)
		return inspectErr == nil && inspect.Agent.Logging.EventData.ToStderr
	}, 2*time.Minute, time.Second, "elastic-agent did not apply the policy change")

	// Ensure the events logs are going to stderr after the policy change.
	require.Eventually(t, func() bool {
		agentOutputStr := agentOutput.String()
		scanner := bufio.NewScanner(strings.NewReader(agentOutputStr))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "Publish event:") {
				return true
			}
		}
		return false
	}, 3*time.Minute, 10*time.Second, "cannot find events on stderr")
}

func applyEventLogStderrPolicy(ctx context.Context, info *define.Info, policyName, policyID, runtime string) error {
	req := kibana.AgentPolicyUpdateRequest{
		Name:      policyName,
		Namespace: info.Namespace,
		Overrides: map[string]any{
			"agent": map[string]any{
				"logging": map[string]any{
					"level": "debug",
					"event_data": map[string]any{
						"to_stderr": true,
						"to_files":  false,
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
		},
	}
	_, err := info.KibanaClient.UpdatePolicy(ctx, policyID, req)
	return err
}

func readEventLogFile(agentFixture *atesting.Fixture) (string, error) {
	glob := filepath.Join(agentFixture.WorkDir(), "data", "elastic-agent-*", "logs", "events", "*")
	files, err := filepath.Glob(glob)
	if err != nil {
		return "", fmt.Errorf("could not scan for events log file: %w", err)
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no events log file found")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		return "", fmt.Errorf("cannot read events log file %s: %w", files[0], err)
	}
	return string(data), nil
}

func eventLogFileContains(agentFixture *atesting.Fixture, expectedStr string) error {
	data, err := readEventLogFile(agentFixture)
	if err != nil {
		return err
	}
	if !strings.Contains(data, expectedStr) {
		return fmt.Errorf("events log file does not contain %q", expectedStr)
	}
	return nil
}

func requireEventLogFileExistsWithData(t *testing.T, agentFixture *atesting.Fixture, expectedStr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return eventLogFileContains(agentFixture, expectedStr) == nil
	}, time.Minute, time.Second,
		"did not find %q in the events log file", expectedStr)
}

func requireNoCopyProcessorError(t *testing.T, agentFixture *atesting.Fixture) {
	t.Helper()
	require.Eventually(t, func() bool {
		return copyProcessorError(agentFixture) == nil
	}, time.Minute, time.Second, "copy_fields processor error found in events log")
}

func copyProcessorError(agentFixture *atesting.Fixture) error {
	data, err := readEventLogFile(agentFixture)
	if err != nil {
		return err
	}
	logEntry := struct {
		LogLogger string `json:"log.logger"`
		Message   string `json:"message"`
	}{}
	for _, line := range strings.Split(data, "\n") {
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			return fmt.Errorf("could not parse log entry: %q", line)
		}
		if logEntry.LogLogger == "copy_fields" &&
			strings.Contains(logEntry.Message, "Failed to copy fields") &&
			strings.Contains(logEntry.Message, "already exists, drop or rename this field first") {
			return fmt.Errorf("copy_fields processor must not fail: %s", logEntry.Message)
		}
	}
	return nil
}

func requireLogFileLayoutForRuntime(t *testing.T, logsDirGlob, runtime string) {
	t.Helper()

	logFileLayoutByRuntime := map[string][]string{
		runtimeProcess: {
			"logs/elastic-agent-*.ndjson",
			"logs/events/elastic-agent-*.ndjson",
		},
		runtimeOtel: {
			"logs/elastic-agent-*.ndjson",
			"logs/elastic-otel-collector-*.ndjson",
			"logs/events/elastic-otel-collector-*.ndjson",
		},
	}

	want, ok := logFileLayoutByRuntime[runtime]
	require.Truef(t, ok, "unknown runtime %q", runtime)

	baseDir := filepath.Dir(logsDirGlob)

	// Every expected pattern must match at least one file.
	expected := map[string]bool{}
	for _, pattern := range want {
		matches, err := filepath.Glob(filepath.Join(baseDir, pattern))
		require.NoErrorf(t, err, "could not glob %q", pattern)
		require.NotEmptyf(t, matches, "expected a log file matching %q under the %s runtime", pattern, runtime)
		for _, m := range matches {
			expected[m] = true
		}
	}

	// No other log files should exist.
	logFiles, err := filepath.Glob(filepath.Join(logsDirGlob, "*.ndjson"))
	require.NoError(t, err, "could not glob log files")
	eventFiles, err := filepath.Glob(filepath.Join(logsDirGlob, "events", "*.ndjson"))
	require.NoError(t, err, "could not glob event log files")
	for _, f := range append(logFiles, eventFiles...) {
		require.Truef(t, expected[f], "unexpected log file %q under the %s runtime", f, runtime)
	}
}

func requireNoEventLeakage(t *testing.T, logsDirGlob string) {
	t.Helper()

	logFiles, err := filepath.Glob(filepath.Join(logsDirGlob, "*.ndjson"))
	require.NoError(t, err, "could not glob log files")
	require.NotEmpty(t, logFiles, "no log files found to check for event leakage")

	for _, f := range logFiles {
		data, err := os.ReadFile(f)
		require.NoErrorf(t, err, "cannot read file %q", f)

		for _, line := range strings.Split(string(data), "\n") {
			if len(line) == 0 {
				continue
			}
			require.NotContainsf(t, line, `"log.type":"event"`,
				"found a log.type:event entry leaked into non-event log file %q", f)
		}
	}
}

func collectDiagnosticsAndVeriflyLogs(
	t *testing.T,
	ctx context.Context,
	agentFixture *atesting.Fixture,
	cmd,
	expectedFiles []string,
) {
	diagPath, err := agentFixture.ExecDiagnostics(ctx, cmd...)
	if err != nil {
		t.Fatalf("could not execute diagnostics excluding events log: %s", err)
	}

	extractionDir := t.TempDir()
	extractZipArchive(t, diagPath, extractionDir)
	diagLogFiles, diagEventLogFiles := getLogFilenames(
		t,
		filepath.Join(extractionDir, "logs", "elastic-agent*"))
	allLogs := append(diagLogFiles, diagEventLogFiles...)

	require.ElementsMatch(
		t,
		expectedFiles,
		allLogs,
		"expected: 'listA', got: 'listB'")
}

func getLogFilenames(
	t *testing.T,
	basepath string,
) (logFiles, eventLogFiles []string) {
	logFilesGlob := filepath.Join(basepath, "*.ndjson")
	logFilesPath, err := filepath.Glob(logFilesGlob)
	if err != nil {
		t.Fatalf("could not get log file names:%s", err)
	}

	for _, f := range logFilesPath {
		logFiles = append(logFiles, filepath.Base(f))
	}

	eventLogFilesGlob := filepath.Join(basepath, "events", "*.ndjson")
	eventLogFilesPath, err := filepath.Glob(eventLogFilesGlob)
	if err != nil {
		t.Fatalf("could not get log file names:%s", err)
	}

	for _, f := range eventLogFilesPath {
		eventLogFiles = append(eventLogFiles, filepath.Base(f))
	}

	return logFiles, eventLogFiles
}
