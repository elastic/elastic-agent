// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent-libs/transport/tlscommontest"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	aTesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/go-elasticsearch/v8"
)

const apmProcessingContent = `2023-06-19 05:20:50 ERROR This is a test error message
2023-06-20 12:50:00 DEBUG This is a test debug message 2
2023-06-20 12:51:00 DEBUG This is a test debug message 3
2023-06-20 12:52:00 DEBUG This is a test debug message 4`

const apmOtelConfig = `receivers:
  filelog:
    include: [ %s ]
    operators:
      - type: regex_parser
        regex: '^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<sev>[A-Z]*) (?P<msg>.*)$'
        timestamp:
          parse_from: attributes.time
          layout: '%%Y-%%m-%%d %%H:%%M:%%S'
        severity:
          parse_from: attributes.sev

processors:
  resource:
    attributes:
    # APM Server will use service.name for data stream name: logs-apm.app.<service_name>-default
    - key: service.name
      action: insert
      value: elastic-otel-test
    - key: host.test-id
      action: insert
      value: %s

exporters:
  debug:
    verbosity: detailed
    sampling_initial: 10000
    sampling_thereafter: 10000
  otlp/elastic:
      endpoint: "127.0.0.1:8200"
      tls:
        insecure: true

service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [resource]
      exporters:
        - debug
        - otlp/elastic`

func TestOtelStartShutdown(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	otelConfig := `receivers:
  nop:
exporters:
  nop:
service:
  pipelines:
    logs:
      receivers:
        - nop
      exporters:
        - nop
`
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.ConfigureOtel(t.Context(), []byte(otelConfig))
	require.NoError(t, err)

	cmd, err := fixture.PrepareAgentCommand(ctx, []string{"otel"})
	require.NoError(t, err)

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	require.NoError(t, cmd.Start(), "could not start otel collector")
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Contains(collect, output.String(), "Everything is ready")
	}, time.Second*30, time.Second)

	// stop the collector and check that it emitted logs indicating a graceful shutdown
	require.NoError(t, cmd.Process.Signal(os.Interrupt))
	require.NoError(t, cmd.Wait())
	assert.Contains(t, output.String(), "Shutdown complete")
}

func TestOtelFileProcessing(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	// replace default elastic-agent.yml with otel config
	// otel mode should be detected automatically
	tmpDir := t.TempDir()
	// create input file
	numEvents := 50
	inputFile, err := os.CreateTemp(tmpDir, "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	inputFilePath := inputFile.Name()
	for i := 0; i < numEvents; i++ {
		_, err = inputFile.Write([]byte(fmt.Sprintf("Line %d\n", i)))
		require.NoErrorf(t, err, "failed to write line %d to temp file", i)
	}
	err = inputFile.Close()
	require.NoError(t, err, "failed to close data temp file")
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(inputFilePath)
			if err != nil {
				t.Logf("no data file to import at %s", inputFilePath)
				return
			}
			t.Logf("contents of import file:\n%s\n", string(contents))
		}
	})
	// create output filename
	outputFilePath := filepath.Join(tmpDir, "output.txt")
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(outputFilePath)
			if err != nil {
				t.Logf("no output data at %s", inputFilePath)
				return
			}
			t.Logf("contents of output file:\n%s\n", string(contents))
		}
	})
	// create the otel config with input and output
	type otelConfigOptions struct {
		InputPath  string
		OutputPath string
	}
	otelConfigTemplate := `receivers:
  filelog:
    include:
      - {{.InputPath}}
    start_at: beginning

exporters:
  file:
    path: {{.OutputPath}}
service:
  pipelines:
    logs:
      receivers:
        - filelog
      exporters:
        - file
`
	otelConfigPath := filepath.Join(tmpDir, "otel.yml")
	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("otelConfig").Parse(otelConfigTemplate)).Execute(&otelConfigBuffer,
			otelConfigOptions{
				InputPath:  inputFilePath,
				OutputPath: outputFilePath,
			}))
	require.NoError(t, os.WriteFile(otelConfigPath, otelConfigBuffer.Bytes(), 0o600))
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(otelConfigPath)
			if err != nil {
				t.Logf("No otel configuration file at %s", otelConfigPath)
				return
			}
			t.Logf("Contents of otel config file:\n%s\n", string(contents))
		}
	})
	// now we can actually run the test

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", otelConfigPath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	// remove elastic-agent.yml, otel should be independent
	require.NoError(t, os.Remove(filepath.Join(fixture.WorkDir(), "elastic-agent.yml")))

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(ctx)
	}()

	validateCommandIsWorking(t, ctx, fixture, tmpDir)

	var content []byte
	require.Eventually(t,
		func() bool {
			// verify file exists
			content, err = os.ReadFile(outputFilePath)
			if err != nil || len(content) == 0 {
				return false
			}

			found := bytes.Count(content, []byte(filepath.Base(inputFilePath)))
			return found == numEvents
		},
		3*time.Minute, 500*time.Millisecond,
		fmt.Sprintf("there should be exported logs by now"))
	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded, "Retrieved unexpected error: %s", err.Error())
}

func TestOtelHybridFileProcessing(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			// input path missing on windows
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	// otel mode should be detected automatically
	tmpDir := t.TempDir()
	// create input file
	numEvents := 50
	inputFile, err := os.CreateTemp(tmpDir, "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	inputFilePath := inputFile.Name()
	for i := 0; i < numEvents; i++ {
		_, err = inputFile.Write([]byte(fmt.Sprintf("Line %d\n", i)))
		require.NoErrorf(t, err, "failed to write line %d to temp file", i)
	}
	err = inputFile.Close()
	require.NoError(t, err, "failed to close data temp file")
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(inputFilePath)
			if err != nil {
				t.Logf("no data file to import at %s", inputFilePath)
				return
			}
			t.Logf("contents of import file:\n%s\n", string(contents))
		}
	})
	// create output filename
	outputFilePath := filepath.Join(tmpDir, "output.txt")
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(outputFilePath)
			if err != nil {
				t.Logf("no output data at %s", inputFilePath)
				return
			}
			t.Logf("contents of output file:\n%s\n", string(contents))
		}
	})
	// create the otel config with input and output
	type otelConfigOptions struct {
		InputPath  string
		OutputPath string
	}
	otelConfigTemplate := `receivers:
  filelog:
    include:
      - {{.InputPath}}
    start_at: beginning

exporters:
  file:
    path: {{.OutputPath}}
service:
  pipelines:
    logs:
      receivers:
        - filelog
      exporters:
        - file
`
	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("otelConfig").Parse(otelConfigTemplate)).Execute(&otelConfigBuffer,
			otelConfigOptions{
				InputPath:  inputFilePath,
				OutputPath: outputFilePath,
			}))

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.Run(ctx, aTesting.State{
			Configure: otelConfigBuffer.String(),
			Reached: func(state *client.AgentState) bool {
				// keep running (context cancel will stop it)
				return false
			},
		})
	}()

	var content []byte
	require.Eventually(t,
		func() bool {
			// verify file exists
			content, err = os.ReadFile(outputFilePath)
			if err != nil || len(content) == 0 {
				return false
			}

			found := bytes.Count(content, []byte(filepath.Base(inputFilePath)))
			return found == numEvents
		},
		3*time.Minute, 500*time.Millisecond,
		fmt.Sprintf("there should be exported logs by now"))

	statusCtx, statusCancel := context.WithTimeout(ctx, 5*time.Second)
	defer statusCancel()

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := fixture.ExecStatus(statusCtx)
		assert.NoError(collect, statusErr)
		// agent should be healthy
		assert.Equal(collect, int(cproto.State_HEALTHY), status.State)
		// we should have no normal components running
		assert.Zero(collect, len(status.Components))

		// we should have filebeatreceiver and metricbeatreceiver running
		otelCollectorStatus := status.Collector
		require.NotNil(collect, otelCollectorStatus)
		assert.Equal(collect, int(cproto.CollectorComponentStatus_StatusOK), otelCollectorStatus.Status)
		return
	}, 1*time.Minute, 1*time.Second)

	cancel()
	fixtureWg.Wait()
}

func validateCommandIsWorking(t *testing.T, ctx context.Context, fixture *aTesting.Fixture, tempDir string) {
	fileProcessingConfig := []byte(`receivers:
  filelog:
    include: [ "/var/log/system.log", "/var/log/syslog"  ]
    start_at: beginning

exporters:
  file:
    path: /tmp/testfileprocessing.json
service:
  pipelines:
    logs:
      receivers: [filelog]
      exporters:
        - file
`)
	cfgFilePath := filepath.Join(tempDir, "otel-valid.yml")
	require.NoError(t, os.WriteFile(cfgFilePath, []byte(fileProcessingConfig), 0o600))

	// check `elastic-agent otel validate` command works for otel config
	cmd, err := fixture.PrepareAgentCommand(ctx, []string{"otel", "validate", "--config", cfgFilePath})
	require.NoError(t, err)

	err = cmd.Run()
	require.NoError(t, err)

	// check feature gate works
	out, err := fixture.Exec(ctx, []string{"otel", "validate", "--config", cfgFilePath, "--feature-gates", "foo.bar"})
	require.Error(t, err)
	require.Contains(t, string(out), `no such feature gate "foo.bar"`)

	// check `elastic-agent otel validate` command works for invalid otel config
	cfgFilePath = filepath.Join(tempDir, "otel-invalid.yml")
	fileInvalidOtelConfig := []byte(`receivers:
  filelog:
    include: [ "/var/log/system.log", "/var/log/syslog"  ]
    start_at: beginning

exporters:
  file:
    path: /tmp/testfileprocessing.json
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [nonexistingprocessor]
      exporters:
        - file
`)
	require.NoError(t, os.WriteFile(cfgFilePath, []byte(fileInvalidOtelConfig), 0o600))

	out, err = fixture.Exec(ctx, []string{"otel", "validate", "--config", cfgFilePath})
	require.Error(t, err)
	require.False(t, len(out) == 0)
	require.Contains(t, string(out), `service::pipelines::logs: references processor "nonexistingprocessor" which is not configured`)
}

var logsIngestionConfigTemplate = `
exporters:
  debug:
    verbosity: basic

  elasticsearch:
    api_key: {{.ESApiKey}}
    endpoint: {{.ESEndpoint}}
    logs_index: {{.TestId}}
    sending_queue:
      wait_for_result: true
      block_on_overflow: true
      enabled: true
      batch:
        min_size: 2000
        max_size: 10000
        flush_timeout: 1s
    mapping:
      mode: none

processors:
  resource/add-test-id:
    attributes:
    - key: test.id
      action: insert
      value: {{.TestId}}

receivers:
  filelog:
    include:
      - {{.InputFilePath}}
    start_at: beginning

service:
  pipelines:
    logs:
      exporters:
        - debug
        - elasticsearch
      processors:
        - resource/add-test-id
      receivers:
        - filelog
  telemetry:
    logs:
      level: DEBUG
      encoding: json
      disable_stacktrace: true
      output_paths:
        - {{.OTelLogFile}}
`

func TestOtelLogsIngestion(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	// Prepare the OTel config.
	testId := info.Namespace

	// Ensure everything is saved in case of test failure
	// this folder is also collected on CI.
	tempDir := aTesting.TempDir(t, "..", "..", "..", "build")
	inputFilePath := filepath.Join(tempDir, "input.log")
	otelLogFilePath := filepath.Join(tempDir, "elastic-agent.ndjson")

	esHost, err := integration.GetESHost()
	require.NoError(t, err, "failed to get ES host")
	require.True(t, len(esHost) > 0)

	esClient := info.ESClient
	require.NotNil(t, esClient)
	esApiKey, err := createESApiKey(esClient)
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)

	logsIngestionConfig := logsIngestionConfigTemplate
	logsIngestionConfig = strings.ReplaceAll(logsIngestionConfig, "{{.ESApiKey}}", esApiKey.Encoded)
	logsIngestionConfig = strings.ReplaceAll(logsIngestionConfig, "{{.ESEndpoint}}", esHost)
	logsIngestionConfig = strings.ReplaceAll(logsIngestionConfig, "{{.InputFilePath}}", inputFilePath)
	logsIngestionConfig = strings.ReplaceAll(logsIngestionConfig, "{{.TestId}}", testId)
	logsIngestionConfig = strings.ReplaceAll(logsIngestionConfig, "{{.OTelLogFile}}", otelLogFilePath)

	cfgFilePath := filepath.Join(tempDir, "otel.yml")
	require.NoError(t, os.WriteFile(cfgFilePath, []byte(logsIngestionConfig), 0o600))

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", cfgFilePath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	// remove elastic-agent.yml, otel should be independent
	require.NoError(t, os.Remove(filepath.Join(fixture.WorkDir(), "elastic-agent.yml")))

	// validate that the configuration is valid
	validateCommandIsWorking(t, ctx, fixture, tempDir)

	// start the collector
	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(ctx)
	}()

	// Write logs to input file.
	logsCount := 10_000
	inputFile, err := os.OpenFile(inputFilePath, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	for i := 0; i < logsCount; i++ {
		_, err = fmt.Fprintf(inputFile, "This is a test log message %d\n", i+1)
		require.NoError(t, err)
	}
	inputFile.Close()

	// It takes about 45s to ingest all files on local tests,
	// so set the timeout to 5min to be on the safe side.
	require.EventuallyWithT(
		t,
		func(c *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetAllLogsForIndexWithContext(
				findCtx,
				esClient,
				testId)
			require.NoError(c, err)
			require.Equalf(
				c,
				logsCount,
				docs.Hits.Total.Value,
				"expecting %d events",
				logsCount)
		},
		5*time.Minute,
		time.Second,
		"did not find the expected number of events")

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded, "Retrieved unexpected error: %s", err.Error())
}

func TestOtelAPMIngestion(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Stack: &define.Stack{},
		Local: true,
		OS: []define.OS{
			// apm server not supported on darwin
			{Type: define.Linux},
		},
	})

	const apmVersionMismatch = "The APM integration must be upgraded"
	const apmReadyLog = "all precondition checks are now satisfied"
	logWatcher := aTesting.NewLogWatcher(t,
		apmVersionMismatch, // apm version mismatch
		apmReadyLog,        // apm ready
	)

	// prepare agent
	testId := info.Namespace
	tempDir := t.TempDir()
	cfgFilePath := filepath.Join(tempDir, "otel.yml")
	fileName := "content.log"
	apmConfig := fmt.Sprintf(apmOtelConfig, filepath.Join(tempDir, fileName), testId)
	require.NoError(t, os.WriteFile(cfgFilePath, []byte(apmConfig), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, fileName), []byte{}, 0o600))

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", cfgFilePath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	// prepare input
	agentWorkDir := fixture.WorkDir()

	err = fixture.EnsurePrepared(ctx)
	require.NoError(t, err)

	componentsDir, err := aTesting.FindComponentsDir(agentWorkDir, "")
	require.NoError(t, err)

	// start apm default config just configure ES output
	esHost, err := integration.GetESHost()
	require.NoError(t, err, "failed to get ES host")
	require.True(t, len(esHost) > 0)

	esClient := info.ESClient
	esApiKey, err := createESApiKey(esClient)
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(esApiKey.APIKey) > 1, "api key is invalid %q", esApiKey)

	apmArgs := []string{
		"run",
		"-e",
		"-E", "output.elasticsearch.hosts=['" + esHost + "']",
		"-E", "output.elasticsearch.api_key=" + fmt.Sprintf("%s:%s", esApiKey.ID, esApiKey.APIKey),
		"-E", "apm-server.host=127.0.0.1:8200",
		"-E", "apm-server.ssl.enabled=false",
	}

	apmPath := filepath.Join(componentsDir, "apm-server")
	var apmFixtureWg sync.WaitGroup
	apmFixtureWg.Add(1)
	apmContext, apmCancel := context.WithCancel(ctx)
	defer apmCancel()
	go func() {
		aTesting.RunProcess(t,
			logWatcher,
			apmContext, 0,
			true, true,
			apmPath, apmArgs...)
		apmFixtureWg.Done()
	}()

	// start agent
	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		fixture.RunOtelWithClient(ctx)
		fixtureWg.Done()
	}()

	// wait for apm to start
	err = logWatcher.WaitForKeys(context.Background(),
		10*time.Minute,
		500*time.Millisecond,
		apmReadyLog,
	)
	require.NoError(t, err, "APM not initialized")

	require.NoError(t, os.WriteFile(filepath.Join(tempDir, fileName), []byte(apmProcessingContent), 0o600))

	// check index
	var hits int
	match := map[string]interface{}{
		"labels.host_test-id": testId,
	}

	// apm mismatch or proper docs in ES

	watchLines := linesTrackMap([]string{
		"This is a test error message",
		"This is a test debug message 2",
		"This is a test debug message 3",
		"This is a test debug message 4",
	})

	// failed to get APM version mismatch in time
	// processing should be running
	var apmVersionMismatchEncountered bool
	require.Eventually(t,
		func() bool {
			if logWatcher.KeyOccured(apmVersionMismatch) {
				// mark skipped to make it explicit it was not successfully evaluated
				apmVersionMismatchEncountered = true
				return true
			}

			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()
			docs, err := estools.GetLogsForIndexWithContext(findCtx, esClient, "logs-apm*", match)
			if err != nil {
				return false
			}

			hits = len(docs.Hits.Hits)
			if hits <= 0 {
				return false
			}

			for _, hit := range docs.Hits.Hits {
				s, found := hit.Source["message"]
				if !found {
					continue
				}

				for k := range watchLines {
					if strings.Contains(fmt.Sprint(s), k) {
						watchLines[k] = true
					}
				}
			}
			return mapAllTrue(watchLines)
		},
		5*time.Minute, 500*time.Millisecond,
		fmt.Sprintf("there should be apm logs by now: %#v", watchLines))

	if apmVersionMismatchEncountered {
		t.Skip("agent version needs to be equal to stack version")
	}

	// cleanup apm
	cancel()
	apmCancel()
	fixtureWg.Wait()
	apmFixtureWg.Wait()
}

func createESApiKey(esClient *elasticsearch.Client) (estools.APIKeyResponse, error) {
	return estools.CreateAPIKey(context.Background(), esClient, estools.APIKeyRequest{Name: "test-api-key", Expiration: "1d"})
}

// getDecodedApiKey returns a decoded API key appropriate for use in beats configurations.
func getDecodedApiKey(keyResponse estools.APIKeyResponse) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(keyResponse.Encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func linesTrackMap(lines []string) map[string]bool {
	mm := make(map[string]bool)
	for _, l := range lines {
		mm[l] = false
	}
	return mm
}

func mapAllTrue(mm map[string]bool) bool {
	for _, v := range mm {
		if !v {
			return false
		}
	}

	return true
}

func mapAtLeastOneTrue(mm map[string]bool) bool {
	for _, v := range mm {
		if v {
			return true
		}
	}

	return false
}

func TestOtelFilestreamInput(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})
	tmpDir := t.TempDir()
	numEvents := 50
	// Create the data file to ingest
	inputFile, err := os.CreateTemp(tmpDir, "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	inputFilePath := inputFile.Name()
	for i := 0; i < numEvents; i++ {
		_, err = inputFile.Write([]byte(fmt.Sprintf("Line %d\n", i)))
		require.NoErrorf(t, err, "failed to write line %d to temp file", i)
	}
	err = inputFile.Close()
	require.NoError(t, err, "failed to close data temp file")
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(inputFilePath)
			if err != nil {
				t.Logf("no data file to import at %s", inputFilePath)
				return
			}
			t.Logf("contents of import file:\n%s\n", string(contents))
		}
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Create the otel configuration file
	type otelConfigOptions struct {
		InputPath  string
		ESEndpoint string
		ESApiKey   string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	decodedApiKey, err := getDecodedApiKey(esApiKey)
	require.NoError(t, err)
	configTemplate := `
inputs:
  - type: filestream
    id: filestream-e2e
    use_output: default
    streams:
      - id: e2e
        data_stream:
          dataset: e2e
        paths:
          - {{.InputPath}}
        prospector.scanner.fingerprint.enabled: false
        file_identity.native: ~
outputs:
  default:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: "{{.ESApiKey}}"
    preset: "balanced"
    ssl.enabled: true
    ssl.verification_mode: full
  monitoring:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: "{{.ESApiKey}}"
    preset: "balanced"
agent:
  monitoring:
    metrics: true
    logs: false
    use_output: monitoring
agent.internal.runtime.filebeat.filestream: otel
`
	index := ".ds-logs-e2e-*"
	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			otelConfigOptions{
				InputPath:  inputFilePath,
				ESEndpoint: esEndpoint,
				ESApiKey:   decodedApiKey,
			}))

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.Configure(ctx, configBuffer.Bytes())

	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err, "cannot prepare Elastic-Agent command: %w", err)

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	err = cmd.Start()
	require.NoError(t, err)

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

	// Make sure find the logs
	actualHits := &struct{ Hits int }{}
	assert.EventuallyWithT(t,
		func(ct *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, index, map[string]interface{}{
				"log.file.path": inputFilePath,
			})
			require.NoError(ct, err)

			actualHits.Hits = docs.Hits.Total.Value
			output, execErr := fixture.ExecStatus(context.Background())
			require.NoError(ct, execErr)
			t.Logf("status output: %v", output)
			assert.Equal(ct, numEvents, actualHits.Hits)
		},
		2*time.Minute, 5*time.Second,
		"Expected %d logs, got %v", numEvents, actualHits)

	metricsIndex := ".ds-metrics-elastic_agent*"
	// Check metrics from self-monitoring
	assert.EventuallyWithT(t,
		func(ct *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, metricsIndex, map[string]interface{}{
				"component.id": "filestream-default",
			})
			require.NoError(ct, err)

			actualHits.Hits = docs.Hits.Total.Value
			output, execErr := fixture.ExecStatus(context.Background())
			require.NoError(ct, execErr)
			t.Logf("status output: %v", output)
			assert.Greater(ct, actualHits.Hits, 0)
		},
		2*time.Minute, 5*time.Second,
		"Expected %d metrics events, got %v", numEvents, actualHits)

	cancel()
}

func TestOTelHTTPMetricsInput(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Create the otel configuration file
	type otelConfigOptions struct {
		InputPath  string
		ESEndpoint string
		ESApiKey   string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	decodedApiKey, err := getDecodedApiKey(esApiKey)
	require.NoError(t, err)
	configTemplate := `
inputs:
  - type: http/metrics
    id: http-metrics-test
    use_output: default
    streams:
    - metricsets:
       - json
      path: "/stats"
      hosts:
        - http://localhost:6790
      period: 5s
      data_stream:
        dataset: e2e
      namespace: "json_namespace"
outputs:
  default:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: "{{.ESApiKey}}"
    preset: "balanced"
agent.monitoring:
  metrics: false
  logs: false
  http:
    enabled: true
    port: 6790
agent.internal.runtime.metricbeat:
  http/metrics: otel
`
	index := ".ds-metrics-e2e-*"
	var configBuffer bytes.Buffer

	template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
		otelConfigOptions{
			ESEndpoint: esEndpoint,
			ESApiKey:   decodedApiKey,
		})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.Configure(ctx, configBuffer.Bytes())

	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err, "cannot prepare Elastic-Agent command: %w", err)

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	err = cmd.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 30*time.Second, 1*time.Second)

	// Make sure find the logs
	actualHits := &struct{ Hits int }{}
	assert.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			query := map[string]interface{}{
				"query": map[string]interface{}{
					"exists": map[string]interface{}{
						"field": "http.json_namespace.beat.cpu.system.ticks",
					},
				},
			}

			docs, err := estools.PerformQueryForRawQuery(findCtx, query, index, info.ESClient)
			require.NoError(t, err)

			actualHits.Hits = docs.Hits.Total.Value
			actualHits.Hits = docs.Hits.Total.Value
			return actualHits.Hits >= 1
		},
		2*time.Minute, 5*time.Second,
		"Expected at least %d logs, got %v", 1, actualHits.Hits)

	cancel()
	cmd.Wait()
}

func TestHybridAgentE2E(t *testing.T) {
	// This test is a hybrid agent test that ingests a single log with
	// filebeat and fbreceiver. It then compares the final documents in
	// Elasticsearch to ensure they have no meaningful differences.
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})
	tmpDir := t.TempDir()
	numEvents := 1
	fbIndex := "logs-generic-default"
	fbReceiverIndex := "logs-generic-default"

	inputFile, err := os.CreateTemp(tmpDir, "input-*.log")
	require.NoError(t, err, "failed to create input log file")
	inputFilePath := inputFile.Name()
	for i := 0; i < numEvents; i++ {
		_, err = inputFile.Write([]byte(fmt.Sprintf("Line %d", i)))
		require.NoErrorf(t, err, "failed to write line %d to temp file", i)
		_, err = inputFile.Write([]byte("\n"))
		require.NoErrorf(t, err, "failed to write newline to input file")
		time.Sleep(100 * time.Millisecond)
	}
	err = inputFile.Close()
	require.NoError(t, err, "failed to close data input file")

	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(inputFilePath)
			if err != nil {
				t.Logf("no data file to import at %s", inputFilePath)
				return
			}
			t.Logf("contents of input file: %s\n", string(contents))
		}
	})

	type configOptions struct {
		InputPath       string
		HomeDir         string
		ESEndpoint      string
		ESApiKey        string
		BeatsESApiKey   string
		FBReceiverIndex string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)

	configTemplate := `agent.logging.level: info
agent.logging.to_stderr: true
inputs:
  - id: filestream-filebeat
    type: filestream
    paths:
      - {{.InputPath}}
    prospector.scanner.fingerprint.enabled: false
    file_identity.native: ~
    use_output: default
    queue.mem.flush.timeout: 0s
    path.home: {{.HomeDir}}/filebeat
outputs:
  default:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: {{.BeatsESApiKey}}
    compression_level: 0
receivers:
  filebeatreceiver:
    filebeat:
      inputs:
        - type: filestream
          id: filestream-fbreceiver
          enabled: true
          paths:
            - {{.InputPath}}
          prospector.scanner.fingerprint.enabled: false
          file_identity.native: ~
    processors:
      - add_host_metadata: ~
      - add_cloud_metadata: ~
      - add_fields:
          fields:
            dataset: generic
            namespace: default
            type: logs
          target: data_stream
      - add_fields:
          fields:
            dataset: generic
          target: event
    output:
      otelconsumer:
    logging:
      level: info
      selectors:
        - '*'
    path.home: {{.HomeDir}}/fbreceiver
    queue.mem.flush.timeout: 0s
exporters:
  debug:
    use_internal_logger: false
    verbosity: detailed
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    compression: none
    api_key: {{.ESApiKey}}
    logs_index: {{.FBReceiverIndex}}
    sending_queue:
      wait_for_result: true # Avoid losing data on shutdown
      block_on_overflow: true
      batch:
        flush_timeout: 1s
service:
  pipelines:
    logs:
      receivers:
        - filebeatreceiver
      exporters:
        - elasticsearch/log
        - debug
`

	beatsApiKey, err := getDecodedApiKey(esApiKey)
	require.NoError(t, err, "error decoding api key")

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			configOptions{
				InputPath:       inputFilePath,
				HomeDir:         tmpDir,
				ESEndpoint:      esEndpoint,
				ESApiKey:        esApiKey.Encoded,
				BeatsESApiKey:   string(beatsApiKey),
				FBReceiverIndex: fbReceiverIndex,
			}))
	configContents := configBuffer.Bytes()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Contents of agent config file:\n%s\n", string(configContents))
		}
	})

	// Now we can actually create the fixture and run it
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, configContents)
	require.NoError(t, err)

	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err)
	cmd.WaitDelay = 1 * time.Second

	var output strings.Builder
	cmd.Stderr = &output
	cmd.Stdout = &output

	err = cmd.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 1*time.Minute, 1*time.Second)

	var docs estools.Documents
	actualHits := &struct {
		Hits int
	}{}
	require.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err = estools.GetLogsForIndexWithContext(findCtx, info.ESClient, ".ds-"+fbIndex+"*", map[string]interface{}{
				"log.file.path": inputFilePath,
			})
			require.NoError(t, err)

			actualHits.Hits = docs.Hits.Total.Value

			return actualHits.Hits == numEvents*2 // filebeat + fbreceiver
		},
		1*time.Minute, 1*time.Second,
		"Expected %d logs in elasticsearch, got: %v", numEvents, actualHits)

	doc1 := docs.Hits.Hits[0].Source
	doc2 := docs.Hits.Hits[1].Source
	ignoredFields := []string{
		// Expected to change between filebeat and fbreceiver
		"@timestamp",
		"agent.ephemeral_id",
		"agent.id",

		// for short periods of time, the beats binary version can be out of sync with the beat receiver version
		"agent.version",

		// Missing from fbreceiver doc
		"elastic_agent.id",
		"elastic_agent.snapshot",
		"elastic_agent.version",

		// only in fbreceiver doc
		"agent.otelcol.component.id",
		"agent.otelcol.component.kind",
	}

	AssertMapsEqual(t, doc1, doc2, ignoredFields, "expected documents to be equal")
	cancel()
	cmd.Wait()
}

func AssertMapsEqual(t *testing.T, m1, m2 mapstr.M, ignoredFields []string, msg string) {
	t.Helper()

	flatM1 := m1.Flatten()
	flatM2 := m2.Flatten()
	for _, f := range ignoredFields {
		// Checking ignored fields is disabled until we resolve an issue with event.ingested not being set
		// in some cases.
		// See https://github.com/elastic/elastic-agent/issues/8486 for details.
		//hasKeyM1, _ := flatM1.HasKey(f)
		//hasKeyM2, _ := flatM2.HasKey(f)
		//
		//if !hasKeyM1 && !hasKeyM2 {
		//	assert.Failf(t, msg, "ignored field %q does not exist in either map, please remove it from the ignored fields", f)
		//}
		flatM1.Delete(f)
		flatM2.Delete(f)
	}
	require.Zero(t, cmp.Diff(flatM1, flatM2), msg)
}

func AssertMapstrKeysEqual(t *testing.T, m1, m2 mapstr.M, ignoredFields []string, msg string) {
	t.Helper()
	// Delete all ignored fields.
	for _, f := range ignoredFields {
		_ = m1.Delete(f)
		_ = m2.Delete(f)
	}

	flatM1 := m1.Flatten()
	flatM2 := m2.Flatten()

	for k := range flatM1 {
		flatM1[k] = ""
	}
	for k := range flatM2 {
		flatM2[k] = ""
	}

	require.Zero(t, cmp.Diff(flatM1, flatM2), msg)
}

func TestFBOtelRestartE2E(t *testing.T) {
	// This test ensures that filebeatreceiver is able to deliver logs even
	// in advent of a collector restart.
	// The input is a file that is being appended to n times during the test.
	// It starts a filebeat receiver, waits for some logs and then stops it.
	// It then restarts the collector for the remaining of the test.
	// At the end it asserts that the unique number of logs in ES is equal to the number of
	// lines in the input file.
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	tmpDir := aTesting.TempDir(t, "..", "..", "..", "build")

	inputFile, err := os.CreateTemp(tmpDir, "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	inputFilePath := inputFile.Name()

	// Create the otel configuration file
	type otelConfigOptions struct {
		InputPath  string
		HomeDir    string
		ESEndpoint string
		ESApiKey   string
		Index      string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	// Use a unique index to avoid conflicts with other parallel runners
	index := strings.ToLower("logs-generic-default-" + randStr(8))
	otelConfigTemplate := `receivers:
  filebeatreceiver:
    filebeat:
      inputs:
        - type: filestream
          id: filestream-end-to-end
          enabled: true
          paths:
            - {{.InputPath}}
          parsers:
            - ndjson:
                document_id: "id"
          prospector.scanner.fingerprint.enabled: false
          file_identity.native: ~
    logging:
      level: info
      selectors:
        - '*'
    path.home: {{.HomeDir}}
    path.logs: {{.HomeDir}}
    queue.mem.flush.timeout: 0s
exporters:
  debug:
    use_internal_logger: false
    verbosity: detailed
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    api_key: {{.ESApiKey}}
    logs_index: {{.Index}}
    sending_queue:
      wait_for_result: true # Avoid losing data on shutdown
      block_on_overflow: true
      batch:
        flush_timeout: 1s
    logs_dynamic_id:
      enabled: true
service:
  pipelines:
    logs:
      receivers:
        - filebeatreceiver
      exporters:
        - elasticsearch/log
        #- debug
  telemetry:
    logs:
      level: DEBUG
      encoding: json
      disable_stacktrace: true
      # Save the logs in a file that is kept if the test fails
      output_paths:
        - {{.HomeDir}}/elastic-agent-logs.ndjson
      error_output_paths:
        - {{.HomeDir}}/elastic-agent-error-logs.ndjosn
`
	otelConfigPath := filepath.Join(tmpDir, "otel.yml")
	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("otelConfig").Parse(otelConfigTemplate)).Execute(&otelConfigBuffer,
			otelConfigOptions{
				InputPath:  inputFilePath,
				HomeDir:    tmpDir,
				ESEndpoint: esEndpoint,
				ESApiKey:   esApiKey.Encoded,
				Index:      index,
			}))
	require.NoError(t, os.WriteFile(otelConfigPath, otelConfigBuffer.Bytes(), 0o600))

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", otelConfigPath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// Write logs to input file
	var inputLinesCounter atomic.Int64
	var stopInputWriter atomic.Bool
	go func() {
		for i := 0; ; i++ {
			if stopInputWriter.Load() {
				break
			}

			_, err = inputFile.Write([]byte(fmt.Sprintf(`{"id": "%d", "message": "%d"}`, i, i)))
			assert.NoErrorf(t, err, "failed to write line %d to temp file", i)
			_, err = inputFile.Write([]byte("\n"))
			assert.NoError(t, err, "failed to write newline to temp file")
			inputLinesCounter.Add(1)
			time.Sleep(100 * time.Millisecond)
		}
		err = inputFile.Close()
		assert.NoError(t, err, "failed to close input file")
	}()

	// Start the collector, ingest some logs and then stop it
	stoppedCh := make(chan int, 1)
	fCtx, cancel := context.WithDeadline(ctx, time.Now().Add(1*time.Minute))
	go func() {
		err = fixture.RunOtelWithClient(fCtx)
		cancel()
		assert.Conditionf(t, func() bool {
			return err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
		}, "unexpected error: %v", err)
		close(stoppedCh)
	}()

	require.EventuallyWithT(
		t,
		func(t *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, ".ds-"+index+"*", map[string]any{
				"log.file.path": inputFilePath,
			})
			require.NoError(t, err)
			got := int(docs.Hits.Total.Value)

			require.GreaterOrEqual(t, got, 10, "")
		},
		time.Minute,
		time.Second,
		"Expecting to ingest at least 10 logs")
	cancel()

	select {
	case <-stoppedCh:
	case <-time.After(30 * time.Second):
		require.Fail(t, "expected the collector to have stopped")
	}

	// Stop generating input data
	stopInputWriter.Store(true)

	// start the collector again for the remaining of the test
	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	fCtx, cancel = context.WithDeadline(ctx, time.Now().Add(5*time.Minute))
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(fCtx)
	}()

	require.EventuallyWithT(
		t,
		func(t *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, ".ds-"+index+"*", map[string]any{
				"log.file.path": inputFilePath,
			})
			require.NoError(t, err)

			uniqueIngestedLogs := make(map[string]struct{})
			for _, hit := range docs.Hits.Hits {
				message, found := hit.Source["message"]
				require.True(t, found, "expected message field in document %q", hit.Source)
				msg, ok := message.(string)
				require.True(t, ok, "expected message field to be a string, got %T", message)
				require.NotContainsf(t, uniqueIngestedLogs, msg, "found duplicated log message %q", msg)
				uniqueIngestedLogs[msg] = struct{}{}
			}

			want := inputLinesCounter.Load()
			got := docs.Hits.Total.Value
			require.EqualValues(t, want, got, "expecting %d hits got %d hits", want, got)
		},
		20*time.Second,
		time.Second,
		"Did not find the expected number of logs")

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded), "Retrieved unexpected error: %s", err.Error())
}

func TestOtelBeatsAuthExtension(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			// {Type: define.Windows}, we don't support otel on Windows yet
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	// Create the otel configuration file
	type otelConfigOptions struct {
		ESEndpoint string
		ESApiKey   string
		Index      string
		CAFile     string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	index := "logs-integration-" + info.Namespace

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// create ca-cert
	caCert, err := tlscommontest.GenCA()
	if err != nil {
		t.Fatalf("could not generate root CA certificate: %s", err)
	}

	caFilePath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFilePath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Leaf.Raw}), 0o777)

	// we pass an incorrect CA to es-exporter
	// but we expect beatsauthextension to replace the exporter's
	// roundtripper with how beats implements it (with given http configuration block)
	// hence we expect events to be indexed to elasticsearch
	// if authextension is not used - this test fails
	otelConfigTemplate := `
extensions:
  beatsauth:
    ssl:
     enabled: true
     verification_mode: none
receivers:
  metricbeatreceiver:
    metricbeat:
      modules:
        - module: system
          enabled: true
          period: 1s
          processes:
            - '.*'
          metricsets:
            - cpu
    queue.mem.flush.timeout: 0s
exporters:
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    api_key: {{.ESApiKey}}
    logs_index: {{.Index}}
    sending_queue:
      wait_for_result: true # Avoid losing data on shutdown
      block_on_overflow: true
      batch:
        flush_timeout: 1s
        min_size: 1
    tls:
      ca_file: {{ .CAFile }}
    auth:
      authenticator: beatsauth
service:
  extensions: [beatsauth]
  pipelines:
    logs:
      receivers:
        - metricbeatreceiver
      exporters:
        - elasticsearch/log
`
	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("otelConfig").Parse(otelConfigTemplate)).Execute(&otelConfigBuffer,
			otelConfigOptions{
				ESEndpoint: esEndpoint,
				ESApiKey:   esApiKey.Encoded,
				Index:      index,
				CAFile:     caFilePath,
			}))

	// configure elastic-agent.yml
	err = fixture.Configure(ctx, otelConfigBuffer.Bytes())

	// prepare agent command
	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err, "cannot prepare Elastic-Agent command: %w", err)

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	// start elastic-agent
	err = cmd.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 30*time.Second, 1*time.Second)

	// Make sure find the logs
	actualHits := &struct{ Hits int }{}
	require.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, ".ds-"+index+"*", map[string]interface{}{
				"metricset.name": "cpu",
			})
			require.NoError(t, err)

			actualHits.Hits = docs.Hits.Total.Value
			return actualHits.Hits >= 1
		},
		2*time.Minute, 1*time.Second,
		"Expected at least %d logs, got %v", 1, actualHits)

	cancel()
}

func TestOtelBeatsAuthExtensionInvalidCertificates(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			// {Type: define.Windows}, we don't support otel on Windows yet
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	// Create the otel configuration file
	type otelConfigOptions struct {
		ESEndpoint string
		ESApiKey   string
		Index      string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	index := "logs-integration-" + info.Namespace

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	otelConfigTemplate := `
extensions:
  beatsauth:
    continue_on_error: true
    ssl:
      enabled: true
      verification_mode: none
      certificate: /nonexistent.pem
      key: /nonexistent.key
      key_passphrase: null
      key_passphrase_path: null
      verification_mode: none
receivers:
  metricbeatreceiver:
    metricbeat:
      modules:
        - module: system
          enabled: true
          period: 1s
          processes:
            - '.*'
          metricsets:
            - cpu
    queue.mem.flush.timeout: 0s
exporters:
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    api_key: {{.ESApiKey}}
    logs_index: {{.Index}}
    sending_queue:
      wait_for_result: true # Avoid losing data on shutdown
      block_on_overflow: true
      batch:
        flush_timeout: 1s
        min_size: 1
    auth:
      authenticator: beatsauth
service:
  extensions: [beatsauth]
  pipelines:
    logs:
      receivers:
        - metricbeatreceiver
      exporters:
        - elasticsearch/log
`
	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("otelConfig").Parse(otelConfigTemplate)).Execute(&otelConfigBuffer,
			otelConfigOptions{
				ESEndpoint: esEndpoint,
				ESApiKey:   esApiKey.Encoded,
				Index:      index,
			}))

	// configure elastic-agent.yml
	err = fixture.Configure(ctx, otelConfigBuffer.Bytes())

	// prepare agent command
	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err, "cannot prepare Elastic-Agent command: %w", err)

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	// start elastic-agent
	err = cmd.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		require.NotNil(collect, status.Collector)
		require.NotNil(collect, status.Collector.ComponentStatusMap)

		pipelines, exists := status.Collector.ComponentStatusMap["pipeline:logs"]
		require.True(collect, exists)

		receiver, exists := pipelines.ComponentStatusMap["receiver:metricbeatreceiver"]
		require.True(collect, exists)
		require.EqualValues(collect, receiver.Status, cproto.State_HEALTHY)

		exporter, exists := pipelines.ComponentStatusMap["exporter:elasticsearch/log"]
		require.True(collect, exists)
		require.EqualValues(collect, exporter.Status, cproto.State_DEGRADED)
	}, 2*time.Minute, 5*time.Second)

	cancel()
}

func TestOutputStatusReporting(t *testing.T) {
	define.Require(t, define.Requirements{
		Sudo:  true,
		Group: integration.Default,
		Local: false,
		Stack: nil,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Create the otel configuration file
	type otelConfigOptions struct {
		StatusReportingEnabled bool
	}
	configTemplate := `
inputs:
  - type: system/metrics
    id: http-metrics-test
    use_output: default
    streams:
    - metricsets:
       - cpu
      period: 1s
      data_stream:
        dataset: e2e
      namespace: "json_namespace"
agent.reload:
  period: 1s
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
    preset: "balanced"
    status_reporting:
      enabled: {{.StatusReportingEnabled}}
agent.monitoring:
  metrics: false
  logs: false
  http:
    enabled: true
    port: 6792
agent.grpc:
    port: 6790
agent.internal.runtime.metricbeat:
  system/metrics: otel
`

	var configBuffer bytes.Buffer
	template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
		otelConfigOptions{
			StatusReportingEnabled: true,
		})
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()

	installOpts := aTesting.InstallOpts{
		NonInteractive: true,
		Privileged:     true,
		Force:          true,
		Develop:        true,
	}

	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.Configure(ctx, configBuffer.Bytes())

	output, err := fixture.InstallWithoutEnroll(ctx, &installOpts)
	require.NoErrorf(t, err, "error install withouth enroll: %s\ncombinedoutput:\n%s", err, string(output))

	require.Eventually(t, func() bool {
		status, err := fixture.ExecStatus(ctx)
		if err != nil {
			t.Logf("waiting for agent degraded: %s", err.Error())
			return false
		}
		return status.State == int(cproto.State_DEGRADED)
	}, 30*time.Second, 1*time.Second)

	// Disable status reporting.
	// This should result in HEALTHY state
	configBuffer.Reset()
	template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
		otelConfigOptions{
			StatusReportingEnabled: false,
		})
	err = fixture.Configure(ctx, configBuffer.Bytes())
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 1*time.Minute, 1*time.Second)

	// Enabled status reporting and keep using localhost.
	// This should result in DEGRADED state
	configBuffer.Reset()
	template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
		otelConfigOptions{
			StatusReportingEnabled: true,
		})
	err = fixture.Configure(ctx, configBuffer.Bytes())
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		status, err := fixture.ExecStatus(ctx)
		if err != nil {
			t.Logf("waiting for agent degraded: %s", err.Error())
			return false
		}
		return status.State == int(cproto.State_DEGRADED)
	}, 30*time.Second, 1*time.Second)

	combinedOutput, err := fixture.Uninstall(ctx, &aTesting.UninstallOpts{Force: true})
	require.NoErrorf(t, err, "error uninstalling classic agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))
}

// This tests that live reloading the log level works correctly
func TestLogReloading(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Stack: &define.Stack{},
	})

	// Flow of the test
	// 1. Start elastic-agent with debug logs
	// 2. Change the log level to info without restarting
	// 3. Ensure no debug logs are printed
	// 4. Set service::telemetry::logs::level: debug
	// 5. Ensure service::telemetry::logs::level is given precedence even when agent logs are set to info

	// Create the otel configuration file
	type otelConfigOptions struct {
		ESEndpoint string
		ESApiKey   string
		Index      string
		CAFile     string
	}

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	logConfig := `
outputs:
  default:
    type: elasticsearch
    hosts:
      - %s
    preset: balanced
    protocol: http	
agent.logging.level: %s
agent.grpc.port: 6793
agent.monitoring.enabled: true
agent.logging.to_stderr: true
agent.reload:
  period: 1s
`

	esURL := integration.StartMockES(t, 0, 0, 0, 0)
	// start with debug logs
	cfg := fmt.Sprintf(logConfig, esURL, "debug")

	require.NoError(t, fixture.Configure(ctx, []byte(cfg)))

	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	if err != nil {
		t.Fatalf("cannot prepare Elastic-Agent command: %s", err)
	}

	observer, zapLogs := observer.New(zap.DebugLevel)
	logger := zap.New(observer)
	zapWriter := &ZapWriter{logger: logger, level: zap.InfoLevel}
	cmd.Stderr = zapWriter
	cmd.Stdout = zapWriter

	require.NoError(t, cmd.Start())

	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 30*time.Second, 1*time.Second)

	// Make sure the Elastic-Agent process is not running before
	// exiting the test
	t.Cleanup(func() {
		// Ignore the error because we cancelled the context,
		// and that always returns an error
		_ = cmd.Wait()
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			zapLogs.All()
		}
	})

	require.Eventually(t, func() bool {
		// we ensure OTel runtime inputs have started with correct level
		// and not just agent logs
		return (zapLogs.FilterMessageSnippet("otelcol.component.kind").FilterMessageSnippet(`"log.level":"debug"`).Len() > 1)
	}, 1*time.Minute, 10*time.Second, "could not find debug logs")

	// set agent.logging.level: info
	cfg = fmt.Sprintf(logConfig, esURL, "info")
	require.NoError(t, fixture.Configure(ctx, []byte(cfg)))

	// wait for elastic agent to be healthy and OTel collector to start
	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return zapLogs.FilterMessageSnippet("Everything is ready. Begin running and processing data").Len() > 1
	}, 90*time.Second, 10*time.Second, "elastic-agent was not healthy after log level changed to info")

	// this debug log should not be present again after re-loading
	require.Equal(t, 1, zapLogs.FilterMessageSnippet(`Starting health check extension V2`).Len())

	// set collector logs to debug
	logConfig = logConfig + `
service:
  telemetry:
    logs:
      level: debug
`

	// reset zap logs
	zapLogs.TakeAll()

	// add service::telemetry::logs::level:debug
	cfg = fmt.Sprintf(logConfig, esURL, "info")
	require.NoError(t, fixture.Configure(ctx, []byte(cfg)))

	// wait for elastic agent to be healthy and OTel collector to re-start
	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return zapLogs.FilterMessageSnippet("Everything is ready. Begin running and processing data").Len() > 0
	}, 1*time.Minute, 10*time.Second, "elastic-agent is not healthy after collector log level was set")

	require.Eventually(t, func() bool {
		// we ensure inputs have reloaded with correct level
		// and not just agent logs
		return (zapLogs.FilterMessageSnippet("otelcol.component.kind").FilterMessageSnippet(`"log.level":"debug"`).Len() > 1)
	}, 1*time.Minute, 10*time.Second, "collector setting for log level was not given precedence")
}

func TestMonitoringReceiver(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	indexName := strings.ToLower("logs-generic-default-" + info.Namespace)

	esHost, err := integration.GetESHost()
	require.NoError(t, err, "failed to get ES host")
	require.True(t, len(esHost) > 0)

	esClient := info.ESClient
	require.NotNil(t, esClient)
	esApiKey, err := createESApiKey(esClient)
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)

	cfg := `
agent.logging.to_stderr: true
receivers:
  elasticmonitoringreceiver:
    interval: 3s
exporters:
  elasticsearch/1:
    endpoints:
      - {{.ESEndpoint}}
    api_key: {{.ESApiKey}}
    max_conns_per_host: 1
    logs_index: {{.Index}}
    retry:
      enabled: true
      initial_interval: 1s
      max_interval: 1m0s
      max_retries: 3
    sending_queue:
      batch:
        flush_timeout: 10s
        max_size: 1
        min_size: 1
        sizer: items
      block_on_overflow: true
      enabled: true
      num_consumers: 1
      queue_size: 3200
      wait_for_result: true

service:
  pipelines:
    logs:
      receivers: [elasticmonitoringreceiver]
      exporters:
        - elasticsearch/1
`

	configParams := struct {
		ESEndpoint string
		ESApiKey   string
		Index      string
	}{
		ESEndpoint: esHost,
		ESApiKey:   esApiKey.Encoded,
		Index:      indexName,
	}

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(cfg)).Execute(&configBuffer, configParams),
	)

	// Create fixture and prepare agent
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.Configure(ctx, configBuffer.Bytes())
	require.NoError(t, err)

	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err)
	cmd.WaitDelay = 1 * time.Second

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	require.NoError(t, cmd.Start(), "could not start otel collector")

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 1*time.Minute, 1*time.Second)

	// Wait for monitoring events to be indexed in Elasticsearch
	var docs estools.Documents
	require.EventuallyWithT(
		t,
		func(c *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer findCancel()

			result, err := estools.GetAllLogsForIndexWithContext(
				findCtx,
				esClient,
				".ds-"+indexName+"*")
			require.NoError(c, err)
			require.Equalf(
				c,
				2,
				result.Hits.Total.Value,
				"expecting exactly 2 monitoring events, got %d",
				result.Hits.Total.Value)
			docs = result
		},
		90*time.Second,
		100*time.Millisecond,
		"did not find the expected number of monitoring events")

	require.Equal(t, 2, len(docs.Hits.Hits), "should have exactly 2 monitoring documents")
	var ev mapstr.M
	ev = docs.Hits.Hits[0].Source
	ev = ev.Flatten()

	require.NotEmpty(t, ev["@timestamp"], "expected @timestamp to be set")
	ev.Delete("@timestamp")
	require.Greater(t, ev["beat.stats.libbeat.output.write.bytes"], float64(0))
	ev.Delete("beat.stats.libbeat.output.write.bytes")

	expected := mapstr.M{
		"beat.stats.libbeat.pipeline.queue.max_events":    float64(3200),
		"beat.stats.libbeat.pipeline.queue.filled.events": float64(0),
		"beat.stats.libbeat.pipeline.queue.filled.pct":    float64(0),
		"beat.stats.libbeat.output.events.total":          float64(1),
		"beat.stats.libbeat.output.events.active":         float64(0),
		"beat.stats.libbeat.output.events.acked":          float64(1),
		"beat.stats.libbeat.output.events.dropped":        float64(0),
		"beat.stats.libbeat.output.events.batches":        float64(1),
		"component.id": "elasticsearch/1",
	}

	require.Empty(t, cmp.Diff(expected, ev), "metrics do not match expected values")

	cancel()
}

type ZapWriter struct {
	logger *zap.Logger
	level  zapcore.Level
}

func (w *ZapWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		w.logger.Check(w.level, msg).Write()
		w.logger.Sync()
	}
	return len(p), nil
}
