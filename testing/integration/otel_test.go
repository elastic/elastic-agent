// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	aTesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
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

func TestOtelFileProcessing(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
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
		Group: Default,
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
	output, err := fixture.ExecStatus(statusCtx)
	require.NoError(t, err, "status command failed")

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded, "Retrieved unexpected error: %s", err.Error())

	assert.NotNil(t, output.Collector)
	assert.Equal(t, 2, output.Collector.Status, "collector status should have been StatusOK")
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
`

func TestOtelLogsIngestion(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
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

	tempDir := t.TempDir()
	inputFilePath := filepath.Join(tempDir, "input.log")

	esHost, err := getESHost()
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

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(ctx)
	}()

	validateCommandIsWorking(t, ctx, fixture, tempDir)

	// Write logs to input file.
	logsCount := 10_000
	inputFile, err := os.OpenFile(inputFilePath, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	for i := 0; i < logsCount; i++ {
		_, err = fmt.Fprintf(inputFile, "This is a test log message %d\n", i+1)
		require.NoError(t, err)
	}
	inputFile.Close()
	t.Cleanup(func() {
		_ = os.Remove(inputFilePath)
	})

	actualHits := &struct{ Hits int }{}
	require.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, esClient, ".ds-logs-generic-default*", map[string]interface{}{
				"Resource.test.id": testId,
			})
			require.NoError(t, err)

			actualHits.Hits = docs.Hits.Total.Value
			return actualHits.Hits == logsCount
		},
		2*time.Minute, 1*time.Second,
		"Expected %v logs, got %v", logsCount, actualHits)

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded, "Retrieved unexpected error: %s", err.Error())
}

func TestOtelAPMIngestion(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
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

	componentsDir, err := aTesting.FindComponentsDir(agentWorkDir)
	require.NoError(t, err)

	// start apm default config just configure ES output
	esHost, err := getESHost()
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
		"-E", "output.elasticsearch.api_key=" + fmt.Sprintf("%s:%s", esApiKey.Id, esApiKey.APIKey),
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

func getESHost() (string, error) {
	fixedESHost := os.Getenv("ELASTICSEARCH_HOST")
	parsedES, err := url.Parse(fixedESHost)
	if err != nil {
		return "", err
	}
	if parsedES.Port() == "" {
		fixedESHost = fmt.Sprintf("%s:443", fixedESHost)
	}
	return fixedESHost, nil
}

func createESApiKey(esClient *elasticsearch.Client) (estools.APIKeyResponse, error) {
	return estools.CreateAPIKey(context.Background(), esClient, estools.APIKeyRequest{Name: "test-api-key", Expiration: "1d"})
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

func TestFileBeatReceiver(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	type otelConfigOptions struct {
		Message string
		Output  string
		HomeDir string
	}
	testMessage := "supercalifragilisticexpialidocious"
	tmpDir := t.TempDir()
	exporterOutputPath := filepath.Join(tmpDir, "output.json")
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(exporterOutputPath)
			if err != nil {
				t.Logf("No exporter output file")
				return
			}
			t.Logf("Contents of exporter output file:\n%s\n", string(contents))
		}
	})
	otelConfigPath := filepath.Join(tmpDir, "otel.yml")
	otelConfigTemplate := `receivers:
  filebeatreceiver:
    filebeat:
      inputs:
        - type: benchmark
          enabled: true
          count: 1
          message: {{.Message}}
    output:
      otelconsumer:
    logging:
      level: info
      selectors:
        - '*'
    path.home: {{.HomeDir}}
exporters:
  file/no_rotation:
    path: {{.Output}}
service:
  pipelines:
    logs:
      receivers: [filebeatreceiver]
      exporters: [file/no_rotation]
`

	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("otelConfig").Parse(otelConfigTemplate)).Execute(&otelConfigBuffer,
			otelConfigOptions{
				Message: testMessage,
				Output:  exporterOutputPath,
				HomeDir: tmpDir,
			}))
	require.NoError(t, os.WriteFile(otelConfigPath, otelConfigBuffer.Bytes(), 0o600))
	t.Cleanup(func() {
		if t.Failed() {
			contents, err := os.ReadFile(otelConfigPath)
			if err != nil {
				t.Logf("no otel config file")
				return
			}
			t.Logf("Contents of otel config file:\n%s\n", string(contents))
		}
	})
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", otelConfigPath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(ctx)
	}()

	require.Eventually(t,
		func() bool {
			content, err := os.ReadFile(exporterOutputPath)
			if err != nil || len(content) == 0 {
				return false
			}
			return bytes.Contains(content, []byte(testMessage))
		},
		3*time.Minute, 1*time.Second,
		fmt.Sprintf("there should be exported logs by now"))

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded, "Retrieved unexpected error: %s", err.Error())
}

func TestOtelFBReceiverE2E(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
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

	// Create the otel configuration file
	type otelConfigOptions struct {
		InputPath  string
		HomeDir    string
		ESEndpoint string
		ESApiKey   string
		Index      string
		MinItems   int
	}
	esEndpoint, err := getESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	index := "logs-integration-default"
	otelConfigTemplate := `receivers:
  filebeatreceiver:
    filebeat:
      inputs:
        - type: filestream
          id: filestream-end-to-end
          enabled: true
          paths:
            - {{.InputPath}}
    output:
      otelconsumer:
    logging:
      level: info
      selectors:
        - '*'
    path.home: {{.HomeDir}}
    queue.mem.flush.timeout: 0s
exporters:
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    api_key: {{.ESApiKey}}
    logs_index: {{.Index}}
    batcher:
      enabled: true
      flush_timeout: 1s
      min_size_items: {{.MinItems}}
    mapping:
      mode: bodymap
service:
  pipelines:
    logs:
      receivers:
        - filebeatreceiver
      exporters:
        - elasticsearch/log
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
				MinItems:   numEvents,
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
	// Now we can actually create the fixture and run it
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", otelConfigPath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(ctx)
	}()

	// Make sure find the logs
	actualHits := &struct{ Hits int }{}
	require.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, ".ds-"+index+"*", map[string]interface{}{
				"log.file.path": inputFilePath,
			})
			require.NoError(t, err)

			actualHits.Hits = docs.Hits.Total.Value
			return actualHits.Hits == numEvents
		},
		2*time.Minute, 1*time.Second,
		"Expected %d logs, got %v", numEvents, actualHits)

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded), "Retrieved unexpected error: %s", err.Error())
}

func TestOtelMBReceiverE2E(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		OS: []define.OS{
			// {Type: define.Windows}, we don't support otel on Windows yet
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})
	tmpDir := t.TempDir()

	// Create the otel configuration file
	type otelConfigOptions struct {
		HomeDir    string
		ESEndpoint string
		ESApiKey   string
		Index      string
		MinItems   int
	}
	esEndpoint, err := getESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	index := "logs-integration-default"
	otelConfigTemplate := `receivers:
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
    output:
      otelconsumer:
    logging:
      level: info
      selectors:
        - '*'
    path.home: {{.HomeDir}}
    queue.mem.flush.timeout: 0s
exporters:
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    api_key: {{.ESApiKey}}
    logs_index: {{.Index}}
    batcher:
      enabled: true
      flush_timeout: 1s
      min_size_items: {{.MinItems}}
    mapping:
      mode: bodymap
service:
  pipelines:
    logs:
      receivers:
        - metricbeatreceiver
      exporters:
        - elasticsearch/log
`
	otelConfigPath := filepath.Join(tmpDir, "otel.yml")
	var otelConfigBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("otelConfig").Parse(otelConfigTemplate)).Execute(&otelConfigBuffer,
			otelConfigOptions{
				HomeDir:    tmpDir,
				ESEndpoint: esEndpoint,
				ESApiKey:   esApiKey.Encoded,
				Index:      index,
				MinItems:   1,
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
	// Now we can actually create the fixture and run it
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", otelConfigPath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(ctx)
	}()

	// Make sure find the logs
	actualHits := &struct{ Hits int }{}
	require.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	fixtureWg.Wait()
	require.True(t, err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded), "Retrieved unexpected error: %s", err.Error())
}

func TestFBOtelRestartE2E(t *testing.T) {
	// This test ensures that filebeatreceiver is able to deliver logs even
	// in advent of a collector restart.
	// The input is a file that is being appended to n times during the test.
	// It starts a filebeat receiver and then restarts it a couple times.
	// At the end it asserts that the number of logs in ES is equal to the number of
	// lines in the input file.
	info := define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})
	tmpDir := t.TempDir()

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
	esEndpoint, err := getESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	index := "logs-integration-default"
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
    output:
      otelconsumer:
    logging:
      level: info
      selectors:
        - '*'
    path.home: {{.HomeDir}}
    queue.mem.flush.timeout: 0s
exporters:
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    api_key: {{.ESApiKey}}
    logs_index: {{.Index}}
    batcher:
      enabled: true
      flush_timeout: 1s
    mapping:
      mode: bodymap
service:
  pipelines:
    logs:
      receivers:
        - filebeatreceiver
      exporters:
        - elasticsearch/log
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
	// Now we can actually create the fixture and run it
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", otelConfigPath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	// Write logs to input file
	var inputLinesCounter atomic.Int64
	var stopInputWriter atomic.Bool
	go func() {
		for i := 0; ; i++ {
			if stopInputWriter.Load() {
				break
			}

			_, err = inputFile.Write([]byte(fmt.Sprintf(`{"id": "%d", "text: "line %d"}\n`, i, i)))
			require.NoErrorf(t, err, "failed to write line %d to temp file", i)
			inputLinesCounter.Add(1)
			time.Sleep(100 * time.Millisecond)
		}
		err = inputFile.Close()
		require.NoError(t, err, "failed to close input file")
	}()

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

	var restartCount atomic.Int64
	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()

		for {
			// restart the collector every couple seconds while new data is being written
			prevCount := inputLinesCounter.Load()
			fCtx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
			err = fixture.RunOtelWithClient(fCtx)
			cancel()
			require.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled), "unexpected error: %v", err)
			require.True(t, inputLinesCounter.Load() > prevCount, "expected input lines to increase")
			restartCount.Add(1)

			if stopInputWriter.Load() {
				break
			}
		}

		// start the collector again for the remaining of the test
		fCtx, cancel := context.WithDeadline(ctx, time.Now().Add(5*time.Minute))
		defer cancel()
		err = fixture.RunOtelWithClient(fCtx)
	}()

	time.Sleep(5 * time.Second)
	stopInputWriter.Store(true)

	require.True(t, restartCount.Load() > 0, "expected the collector to restart at least once")

	// Make sure all the logs are ingested
	actualHits := &struct{ Hits int }{}
	require.Eventually(t,
		func() bool {
			findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer findCancel()

			docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, ".ds-"+index+"*", map[string]interface{}{
				"log.file.path": inputFilePath,
			})
			require.NoError(t, err)

			actualHits.Hits = docs.Hits.Total.Value
			return actualHits.Hits == int(inputLinesCounter.Load())
		},
		2*time.Minute, 1*time.Second,
		"Expected %d logs, got %v", int(inputLinesCounter.Load()), actualHits)

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded), "Retrieved unexpected error: %s", err.Error())
}
