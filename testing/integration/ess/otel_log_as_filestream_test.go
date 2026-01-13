// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent-libs/testing/fs"
	"github.com/elastic/elastic-agent/pkg/core/process"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestFilebeatReceiverLogAsFilestream test beats receivers as follow:
//  1. Runs Filebeat Receiver with the Log input
//  2. Ensures all events are ingested
//  3. Stops Filebeat Receiver
//  4. Starts Filebeat Receiver with the global feature flag enabled
//  5. Adds more data to the file
//  6. Ensures all data is ingested and no duplication happens
func TestFilebeatReceiverLogAsFilestream(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	otelConfigTemplate := `receivers:
  filebeatreceiver:
    filebeat:
      inputs:
        - type: log
          id: a-unique-id
          allow_deprecated_use: true
          paths:
            {{.LogFilepath}}
          fields:
            find_me: {{.Namespace}}
    output:
      otelconsumer:
    logging:
      level: debug
      selectors:
        - '*'
    path.home: {{.HomeDir}}
    features.log_input_run_as_filestream.enabled: {{.AsFilestream}}

exporters:
  elasticsearch:
    api_key: {{.ESApiKey}}
    endpoint: {{.ESEndpoint}}
    logs_index: {{.Namespace}}
    sending_queue:
      enabled: true
      wait_for_result: true # Avoid losing data on shutdown
      block_on_overflow: true
    mapping:
      mode: none

service:
  pipelines:
    logs:
      receivers: [filebeatreceiver]
      exporters: [elasticsearch]
  telemetry:
    logs:
      level: DEBUG
      encoding: json
      disable_stacktrace: true
`

	waitEventsInES := func(want int) {
		t.Helper()

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer findCancel()

			docs, err := estools.GetAllLogsForIndexWithContext(
				findCtx,
				info.ESClient,
				info.Namespace)
			require.NoError(c, err)

			got := docs.Hits.Total.Value
			require.Equalf(
				c,
				want,
				got,
				"expecting %d events, got %d",
				want,
				got)
		}, 60*time.Second, time.Second, "did not find the expected number of events")
	}

	rootDir, err := filepath.Abs(filepath.Join("..", "..", "..", "build"))
	require.NoError(t, err, "cannot get absolute path of rootDir")

	tmpDir := fs.TempDir(t, rootDir)
	inputFilePath, err := filepath.Abs(filepath.Join(tmpDir, "log.log"))

	// Generate a string we can use to search in the logs,
	// without it tests on Windows will fail
	inputFilePathStr := strings.ReplaceAll(inputFilePath, `\`, `\\`)

	WriteLogFile(t, inputFilePath, 50, false)

	esApiKey := createESApiKey(t, info.ESClient)
	esHost, err := integration.GetESHost()
	require.NoError(t, err, "failed to get ES host")

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(2*time.Minute))
	defer cancel()

	agentLogFile := fs.NewLogFile(t, tmpDir, t.Name())

	cfg := map[string]any{
		"HomeDir":      tmpDir,
		"LogFilepath":  inputFilePath,
		"ESApiKey":     esApiKey.Encoded,
		"ESEndpoint":   esHost,
		"Namespace":    info.Namespace,
		"AsFilestream": false,
	}

	fixture, err := define.NewFixtureFromLocalBuild(
		t,
		define.Version())
	require.NoError(t, err, "cannot create Elastic Agent fixture")

	// Start Elastic Agent/Filebeat receiver running the Log input
	otelConfigPath := filepath.Join(tmpDir, "otel.yml")
	cmd := StartElasticAgentOtel(t, ctx, otelConfigTemplate, otelConfigPath, cfg, fixture, agentLogFile.File)
	agentLogFile.WaitLogsContains(
		t,
		"Log input (deprecated) running as Log input (deprecated)",
		20*time.Second,
		"Log input did not start as Log input",
	)

	// Wait for all events to be ingested and stop Elastic Agent
	waitEventsInES(50)
	StopElasticAgentOtel(t, cmd, agentLogFile)

	// Enable the feature flag and start Elastic Agent
	cfg["AsFilestream"] = true
	cmd = StartElasticAgentOtel(t, ctx, otelConfigTemplate, otelConfigPath, cfg, fixture, agentLogFile.File)

	// Ensure the Filesteam input starts
	agentLogFile.WaitLogsContains(
		t,
		"Log input (deprecated) running as Filestream input",
		20*time.Second,
		"Log input did not start as Filestream input",
	)

	agentLogFile.WaitLogsContains(
		t,
		"Input 'filestream' starting",
		20*time.Second,
		"Filestream did not start",
	)

	// Add 50 events to the file, it now contains 100 events
	WriteLogFile(t, inputFilePath, 50, true)

	agentLogFile.WaitLogsContains(
		t,
		"File "+inputFilePathStr+" has been updated",
		20*time.Second,
		"Filestream did not detect change in the file")

	// Wait for Filestream to finish reading the file
	agentLogFile.WaitLogsContains(
		t,
		"End of file reached: "+inputFilePathStr+"; Backoff now",
		20*time.Second,
		"Filestream did not reach EOF")

	// Ensure all 100 events have been ingested and stop Elastic Agent
	waitEventsInES(100)
	StopElasticAgentOtel(t, cmd, agentLogFile)

	// Start Elastic Agent again to ensure it is correctly tracking the state
	cmd = StartElasticAgentOtel(t, ctx, otelConfigTemplate, otelConfigPath, cfg, fixture, agentLogFile.File)
	agentLogFile.WaitLogsContains(
		t,
		"Log input (deprecated) running as Filestream input",
		20*time.Second,
		"Log input did not start as Filestream input",
	)

	agentLogFile.WaitLogsContains(
		t,
		"Input 'filestream' starting",
		20*time.Second,
		"Filestream did not start",
	)

	agentLogFile.WaitLogsContains(
		t,
		"End of file reached: "+inputFilePathStr+"; Backoff now.",
		20*time.Second,
		"Filestream did not reach EOF")

	// Stop Elastic Agent
	StopElasticAgentOtel(t, cmd, agentLogFile)

	// Ensure there was no data duplication
	waitEventsInES(100)
}

func StartElasticAgentOtel(
	t *testing.T,
	ctx context.Context,
	otelConfigTemplate string,
	otelConfigPath string,
	cfg map[string]any,
	fixture *atesting.Fixture,
	f *os.File) *exec.Cmd {

	otelConfigBuffer := bytes.Buffer{}
	require.NoError(t,
		template.Must(
			template.New("otelConfig").
				Parse(otelConfigTemplate)).
			Execute(
				&otelConfigBuffer,
				cfg))

	require.NoError(
		t,
		os.WriteFile(otelConfigPath, otelConfigBuffer.Bytes(), 0o600),
		"cannot write configuration file")

	cmd, err := fixture.PrepareAgentCommand(
		ctx,
		[]string{"otel", "--config", otelConfigPath},
	)
	require.NoError(t, err, "cannot prepare Elastic Agent command")

	cmd.Stderr = f
	cmd.Stdout = f

	require.NoError(t, cmd.Start(), "cannot start Elastic Agent in OTel mode")

	return cmd
}

func StopElasticAgentOtel(t *testing.T, cmd *exec.Cmd, f *fs.LogFile) {
	require.NoError(
		t,
		process.Terminate(cmd.Process),
		"cannot send terminate signal to Elastic Agent")

	// On Windows cmd.Wait always returns an error: exit status 0xc000013a
	// and the process is not gracefully terminated, so we ignore those checks.
	if runtime.GOOS == "windows" {
		cmd.Wait()
		return
	}

	require.NoError(t, cmd.Wait(), "Elastic Agent exited with an error")

	f.WaitLogsContains(
		t,
		"Shutdown complete.",
		time.Second,
		"Filebeat Receiver didn't shutdown")
}

// WriteLogFile writes count lines to path.
// Each line contains the current time (RFC3339) and a counter.
// Prefix is added instead of current time if it exists.
// If no prefix is passed, each line is 50 bytes long
func WriteLogFile(t *testing.T, path string, count int, append bool, prefix ...string) {
	var file *os.File
	var err error
	if !append {
		file, err = os.Create(path)
		if err != nil {
			t.Fatalf("could not create file '%s': %s", path, err)
		}
	} else {
		file, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
		if err != nil {
			t.Fatalf("could not open or create file: '%s': %s", path, err)
		}
	}

	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("could not close file: %s", err)
		}
	}()
	defer func() {
		if err := file.Sync(); err != nil {
			t.Fatalf("could not sync file: %s", err)
		}
	}()

	var now string
	if len(prefix) == 0 {
		// If the length is different, e.g when there is no offset from UTC.
		// add some padding so the length is predictable
		now = time.Now().Format(time.RFC3339)
		if len(now) != len(time.RFC3339) {
			paddingNeeded := len(time.RFC3339) - len(now)
			for range paddingNeeded {
				now += "-"
			}
		}
	} else {
		now = strings.Join(prefix, "")
	}

	for i := range count {
		if _, err := fmt.Fprintf(file, "%s           %13d\n", now, i); err != nil {
			t.Fatalf("could not write line %d to file: %s", count+1, err)
		}
	}
}
