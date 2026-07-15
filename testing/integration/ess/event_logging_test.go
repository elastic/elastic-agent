// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
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
		Sudo:  false,
	})

	for _, runtime := range allRuntimes {
		t.Run(runtime, func(t *testing.T) {
			ctx, cancel := testcontext.WithDeadline(
				t,
				t.Context(),
				time.Now().Add(10*time.Minute))
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

			// Make sure the Elastic-Agent process is not running before
			// exiting the test
			t.Cleanup(func() {
				// Ignore the error because we cancelled the context,
				// and that always returns an error
				_ = cmd.Wait()
				if t.Failed() {
					t.Log("Elastic-Agent output:")
					t.Log(output.String())
				}
			})

			// Now the Elastic-Agent is running, so validate the Event log file.
			requireEventLogFileExistsWithData(t, agentFixture, "Publish event: ")
			requireNoCopyProcessorError(t, agentFixture)

			logsDirGlob := filepath.Join(agentFixture.WorkDir(),
				"data", "elastic-agent-*", "logs")
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
		})
	}
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

func TestEventLogOutputConfiguredViaFleet(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: "container",
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	_, outputID := createMockESOutput(t, info, 0, 0, 100, 0)
	policyName := fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String())
	policyID, enrollmentAPIKey := createPolicy(
		t,
		ctx,
		agentFixture,
		info,
		policyName,
		outputID)

	// Debug level is required for event log lines to be emitted under the otel runtime.
	debugLoggingUpdateReq := kibana.AgentPolicyUpdateRequest{
		Name:      policyName,
		Namespace: info.Namespace,
		Overrides: map[string]any{
			"agent": map[string]any{
				"logging": map[string]any{
					"level": "debug",
				},
			},
		},
	}

	_, err = info.KibanaClient.UpdatePolicy(ctx,
		policyID, debugLoggingUpdateReq)
	require.NoError(t, err)

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
		t.Fatalf("error enrolling Elastic-Agent: %s\nOutput:\n%s", err, string(out))
	}

	runAgentCMD, agentOutput := prepareAgentCMD(t, ctx, agentFixture, nil, nil)
	if err := runAgentCMD.Start(); err != nil {
		t.Fatalf("could not start Elastic-Agent: %s", err)
	}

	assert.Eventuallyf(t, func() bool {
		// This will return errors until it connects to the agent,
		// they're mostly noise because until the agent starts running
		// we will get connection errors. If the test fails
		// the agent logs will be present in the error message
		// which should help to explain why the agent was not
		// healthy.
		err := agentFixture.IsHealthy(ctx)
		return err == nil
	},
		2*time.Minute, time.Second,
		"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
		err, agentOutput,
	)

	// The default behaviour is to log events to the events log file
	// so ensure this is happening
	// As the mockEs returns indexing failures, we should see "Cannot index event" in the events log file
	requireEventLogFileExistsWithData(t, agentFixture, "Cannot index event")

	// Add a policy overwrite to change the events output to stderr
	addOverwriteToPolicy(t, info, policyName, policyID)

	// Ensure Elastic-Agent is healthy after the policy change
	assert.Eventuallyf(t, func() bool {
		// This will return errors until it connects to the agent,
		// they're mostly noise because until the agent starts running
		// we will get connection errors. If the test fails
		// the agent logs will be present in the error message
		// which should help to explain why the agent was not
		// healthy.
		err := agentFixture.IsHealthy(ctx)
		return err == nil
	},
		2*time.Minute, time.Second,
		"Elastic-Agent did not report healthy after policy change. Agent status error: \"%v\", Agent logs\n%s",
		err, agentOutput,
	)

	// Ensure the events logs are going to stderr
	assert.Eventually(t, func() bool {
		agentOutputStr := agentOutput.String()
		scanner := bufio.NewScanner(strings.NewReader(agentOutputStr))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "Cannot index event") {
				return true
			}
		}

		return false
	}, 3*time.Minute, 10*time.Second, "cannot find events on stderr")
}

func addOverwriteToPolicy(t *testing.T, info *define.Info, policyName, policyID string) {
	t.Helper()
	body := fmt.Sprintf(`
{
  "name": "%s",
  "namespace": "%s",
  "overrides": {
    "agent": {
      "logging": {
        "level": "debug",
        "event_data": {
          "to_stderr": true,
          "to_files": false
        }
      }
    }
  }
}`, policyName, info.Namespace)
	sendPolicyUpdate(t, info, policyID, body)
}

func readEventLogFile(t *testing.T, agentFixture *atesting.Fixture) string {
	// Now the Elastic-Agent is running, so validate the Event log file.
	// Because the path changes based on the Elastic-Agent version, we
	// use glob to find the file
	var logFileName string
	require.Eventually(t, func() bool {
		// We ignore this error because the folder might not be there.
		// Once the folder and file are there, then this call should succeed
		// and we can read the file.
		glob := filepath.Join(
			agentFixture.WorkDir(),
			"data", "elastic-agent-*", "logs", "events", "*")
		files, err := filepath.Glob(glob)
		if err != nil {
			t.Fatalf("could not scan for the events log file: %s", err)
		}

		if len(files) >= 1 {
			logFileName = files[0]
			return true
		}

		return false
	}, time.Minute, time.Second, "could not find event log file")

	logEntryBytes, err := os.ReadFile(logFileName)
	if err != nil {
		t.Fatalf("cannot read file '%s': %s", logFileName, err)
	}

	return string(logEntryBytes)
}

func requireNoCopyProcessorError(t *testing.T, agentFixture *atesting.Fixture) {
	data := readEventLogFile(t, agentFixture)
	for _, line := range strings.Split(data, "\n") {
		logEntry := struct {
			LogLogger string `json:"log.logger"`
			Message   string `json:"message"`
		}{}

		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			t.Fatalf("could not parse log entry: %q", line)
		}

		if logEntry.LogLogger == "copy_fields" {
			if strings.Contains(logEntry.Message, "Failed to copy fields") {
				if strings.Contains(logEntry.Message, "already exists, drop or rename this field first") {
					t.Fatal("copy_fields processor must not fail")
				}
			}
		}
	}
}

func requireEventLogFileExistsWithData(t *testing.T, agentFixture *atesting.Fixture, expectedStr string) {
	logEntry := readEventLogFile(t, agentFixture)
	// That's part of the generated event that is logged by the 'processor'
	// logger at level debug
	if !strings.Contains(logEntry, expectedStr) {
		t.Errorf(
			"did not find the expected log entry ('%s') in the events log file",
			expectedStr)
		t.Log("Event log file contents:")
		t.Log(logEntry)
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

func sendPolicyUpdate(t *testing.T, info *define.Info, policyID, body string) {
	t.Helper()

	resp, err := info.KibanaClient.Send(
		http.MethodPut,
		fmt.Sprintf("/api/fleet/agent_policies/%s", policyID),
		nil,
		nil,
		bytes.NewBufferString(body),
	)
	if err != nil {
		t.Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respDump, dumpErr := httputil.DumpResponse(resp, true)
		if dumpErr != nil {
			t.Fatalf("could not dump Kibana error response: %s", dumpErr)
		}
		t.Log("Kibana error response:")
		t.Log(string(respDump))
		t.Fatalf("received non-200 status when updating Fleet policy: %d", resp.StatusCode)
	}
}
