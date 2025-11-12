// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"

	libbeatinteg "github.com/elastic/beats/v7/libbeat/tests/integration"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestFilebeatReceiverLogAsFilestream(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			// {Type: define.Windows},
			{Type: define.Linux},
			// {Type: define.Darwin},
		},
	})

	tmpDir := t.TempDir()
	tmpDir = os.TempDir()
	logFilepath := filepath.Join(tmpDir, "log.log")
	numEvents := 50
	libbeatinteg.WriteLogFile(t, logFilepath, numEvents, false)

	exporterOutputPath := filepath.Join(tmpDir, "output.json")
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(exporterOutputPath)
			if err != nil {
				t.Logf("No exporter output file")
				return
			}
			t.Logf("Otel output file path: %s", exporterOutputPath)
			t.Logf("Contents of exporter output file:\n%s\n", string(contents))
		}
	})

	otelConfigPath := filepath.Join(tmpDir, "otel.yml")
	otelConfigTemplate := `receivers:
  filebeatreceiver:
    filebeat:
      inputs:
        - type: log
          id: foo
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

	esClient := info.ESClient
	esApiKey, err := createESApiKey(esClient)
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	esHost, err := integration.GetESHost()
	require.NoError(t, err, "failed to get ES host")
	require.True(t, len(esHost) > 0)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(1*time.Minute))
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(
		t,
		define.Version())
	require.NoError(t, err)

	f := NewLogFile(t)
	f.KeepLogFile = true

	cfg := map[string]any{
		"Output":       exporterOutputPath,
		"HomeDir":      tmpDir,
		"LogFilepath":  logFilepath,
		"ESApiKey":     esApiKey.Encoded,
		"ESEndpoint":   esHost,
		"Namespace":    info.Namespace,
		"AsFilestream": false,
	}

	cmd := start(t, ctx, otelConfigTemplate, otelConfigPath, cfg, fixture, f.File)
	f.WaitLogsContains(
		t,
		"Log input running as Log input",
		20*time.Second,
		"Log input did not start as Log input",
	)

	require.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(
				findCtx,
				esClient,
				".ds-logs-generic-default*",
				map[string]any{
					"Body.fields.find_me": info.Namespace,
				})
			require.NoError(t, err)

			return docs.Hits.Total.Value == numEvents
		},
		30*time.Second, 1*time.Second,
		"Expected %v logs", numEvents)

	stop(t, cmd, f)

	//================================================== Run again
	t.Log("================================================== RUNNING AGAIN")
	cmd = start(t, ctx, otelConfigTemplate, otelConfigPath, cfg, fixture, f.File)

	t.Log("==================== Waiting for the second start")
	f.WaitLogsContains(
		t,
		"Log input running as Log input",
		20*time.Second,
		"Log input did not start as Log input",
	)

	// Ensure no new data has been added
	f.WaitLogsContains(
		t,
		"File didn't change: /tmp/log.log",
		20*time.Second,
		"did not reach EOF")

	stop(t, cmd, f)

	cfg["AsFilestream"] = true
	cmd = start(t, ctx, otelConfigTemplate, otelConfigPath, cfg, fixture, f.File)
	t.Log("==================== Waiting for the third start")
	f.WaitLogsContains(
		t,
		"Log input running as Filestream input",
		20*time.Second,
		"Log input did not start as Filestream input",
	)

	f.WaitLogsContains(
		t,
		"Input 'filestream' starting",
		20*time.Second,
		"Filestream did not start",
	)

	f.WaitLogsContains(
		t,
		"End of file reached: /tmp/log.log; Backoff now.",
		20*time.Second,
		"Filestream did not reach EOF")

	stop(t, cmd, f)
}

func start(
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
	require.NoError(t, os.WriteFile(otelConfigPath, otelConfigBuffer.Bytes(), 0o600))

	t.Log("================================================== Start starting")

	cmd, err := fixture.PrepareAgentCommand(
		ctx,
		[]string{"otel", "--config", otelConfigPath},
	)
	require.NoError(t, err)

	cmd.Stderr = f
	cmd.Stdout = f

	if err := cmd.Start(); err != nil {
		t.Errorf("cannot start Elastic Agent in OTel mode: %s", err)
	}

	return cmd
}

func stop(t *testing.T, cmd *exec.Cmd, f *LogFile) {
	t.Log("==================== Sending Interrupt signal")
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("cannot send interrupt signal to Elastic Agent: %s", err)
	}

	t.Log("==================== Waiting process to return")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Elastic Agent exited with an error: %s", err)
	}

	f.WaitLogsContains(t, "Shutdown complete.", time.Second, "Filebeat Receiver didn't shutdown")
}
