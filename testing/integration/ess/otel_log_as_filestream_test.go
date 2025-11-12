// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	libbeatinteg "github.com/elastic/beats/v7/libbeat/tests/integration"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	aTesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/stretchr/testify/require"
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

	type otelConfigOptions struct {
		Message      string
		Output       string
		HomeDir      string
		LogFilepath  string
		AsFilestream bool
		ESApiKey     string
		ESEndpoint   string
		Namespace    string
	}

	tmpDir := t.TempDir()
	tmpDir = os.TempDir()
	logFilepath := filepath.Join(tmpDir, "log.log")
	numEvents := 50
	libbeatinteg.WriteLogFile(t, logFilepath, numEvents, false)

	exporterOutputPath := filepath.Join(tmpDir, "output.json")
	// t.Cleanup(func() {
	// 	if t.Failed() {
	// 		contents, err := os.ReadFile(exporterOutputPath)
	// 		if err != nil {
	// 			t.Logf("No exporter output file")
	// 			return
	// 		}
	// 		t.Logf("Otel output file path: %s", exporterOutputPath)
	// 		t.Logf("Contents of exporter output file:\n%s\n", string(contents))
	// 	}
	// })

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

	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(
			template.New("otelConfig").
				Parse(otelConfigTemplate)).
			Execute(
				&otelConfigBuffer,
				otelConfigOptions{
					Output:      exporterOutputPath,
					HomeDir:     tmpDir,
					LogFilepath: logFilepath,
					ESApiKey:    esApiKey.Encoded,
					ESEndpoint:  esHost,
					Namespace:   info.Namespace,
				}))
	require.NoError(t, os.WriteFile(otelConfigPath, otelConfigBuffer.Bytes(), 0o600))
	// t.Cleanup(func() {
	// 	if t.Failed() {
	// 		contents, err := os.ReadFile(otelConfigPath)
	// 		if err != nil {
	// 			t.Logf("no otel config file")
	// 			return
	// 		}
	// 		t.Logf("Contents of otel config file:\n%s\n", string(contents))
	// 	}
	// })

	fixture, err := define.NewFixtureFromLocalBuild(
		t,
		define.Version(),
		aTesting.WithAdditionalArgs([]string{"--config", otelConfigPath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(1*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	cmd, err := fixture.PrepareAgentCommand(
		ctx,
		[]string{"otel", "--config", otelConfigPath, "-e"},
	)
	require.NoError(t, err)

	// var fixtureWg sync.WaitGroup
	// fixtureWg.Add(1)
	// go func() {
	// 	defer fixtureWg.Done()
	// err = fixture.RunOtelWithClient(ctx)

	f, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("cannot create file: %s", err)
	}

	t.Cleanup(func() {
		t.Logf("Output file: %s", f.Name())
	})

	defer f.Close()

	cmd.Stderr = f
	cmd.Stdout = f

	if err := cmd.Start(); err != nil {
		t.Errorf("cannot start Elastic Agent in OTel mode: %s", err)
	}

	// out, err := cmd.CombinedOutput()
	// if err != nil {
	// 	t.Errorf("combined output returned error: %#v", err)
	// }
	// fmt.Println(string(out))

	// }()

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

	t.Log("==================== Sending Interrupt signal")
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("cannot send interrupt signal to Elastic Agent: %s", err)
	}

	t.Log("==================== Waiting process to return")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Elastic Agent exited with an error: %s", err)
	}
	// cancel()
	// fixtureWg.Wait()
	// require.True(
	// 	t,
	// 	err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
	// 	"Retrieved unexpected error: %s",
	// 	err)

	//================================================== Run again
	// t.Log("================================================== RUNNING AGAIN")
}

func countOtelEvents(t *testing.T, path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}

		// t.Logf("cannot read output file: %s", err)
		return -1
	}

	out := otelOutput{}
	if err := json.Unmarshal(data, &out); err != nil {
		// t.Logf("cannot unmarshal data: %s", err)
		return -1
	}

	count := 0
	for _, rlogs := range out.ResourceLogs {
		for _, slogs := range rlogs.ScopeLogs {
			count += len(slogs.LogRecords)
			// for _, _ := range slogs.LogRecords {
			// 	count++
			// 	// t.Logf("data: %s", lr.Body.KvlistValue.Values)
			// }
		}
	}

	return count
}

type otelOutput struct {
	ResourceLogs []ResourceLogs `json:"resourceLogs"`
}

type ResourceLogs struct {
	ScopeLogs []ScopeLogs `json:"scopeLogs"`
}

type ScopeLogs struct {
	LogRecords []LogRecords `json:"logRecords"`
}

type LogRecords struct {
	TimeUnixNano         string `json:"timeUnixNano"`
	ObservedTimeUnixNano string `json:"observedTimeUnixNano"`
	Body                 Body   `json:"body"`
}

type Body struct {
	KvlistValue KvlistValue `json:"kvlistValue"`
}

type KvlistValue struct {
	Values []Values `json:"values"`
}

type Values struct {
	Key   string `json:"key"`
	Value Value  `json:"value"`
}

type Value struct {
	StringValue string `json:"stringValue"`
}
