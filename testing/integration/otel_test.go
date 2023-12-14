// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	aTesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/go-elasticsearch/v8"
)

const fileProcessingFilename = `/tmp/testfileprocessing.json`

var fileProcessingConfig = []byte(`receivers:
  filelog:
    include: [ "/var/log/system.log", "/var/log/syslog"  ]
    start_at: beginning

exporters:
  file:
    path: ` + fileProcessingFilename + `
service:
  pipelines:
    logs:
      receivers: [filelog]
      exporters:
        - file`)

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
			// input path missing on windows
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	t.Cleanup(func() {
		_ = os.Remove(fileProcessingFilename)
	})

	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent, fakeShipper)
	require.NoError(t, err)

	// replace default elastic-agent.yml with otel config
	// otel mode should be detected automatically
	err = fixture.Configure(ctx, fileProcessingConfig)
	require.NoError(t, err)

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunWithClient(ctx, false)
	}()

	require.Eventually(t,
		func() bool {
			// verify file exists
			content, err := os.ReadFile(fileProcessingFilename)
			return err == nil && len(content) > 0
		},
		5*time.Minute, 500*time.Millisecond,
		"there should be exported logs by now")

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
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent, fakeShipper)
	require.NoError(t, err)

	// prepare input
	agentWorkDir := fixture.WorkDir()
	fileName := "content.log"
	fixture.WriteFileToWorkDir(ctx, "", fileName)

	testId := info.Namespace

	apmConfig := fmt.Sprintf(apmOtelConfig, filepath.Join(agentWorkDir, fileName), testId)

	err = fixture.Configure(ctx, []byte(apmConfig))
	require.NoError(t, err)

	componentsDir, err := aTesting.FindComponentsDir(agentWorkDir)
	require.NoError(t, err)

	// start apm default config just configure ES output
	esHost, err := getESHost()
	require.NoError(t, err, "failed to get ES host")
	require.True(t, len(esHost) > 0)

	esUsername := os.Getenv("ELASTICSEARCH_USERNAME")
	require.True(t, len(esUsername) > 0)

	esPass := os.Getenv("ELASTICSEARCH_PASSWORD")
	require.True(t, len(esPass) > 0)

	esClient := info.ESClient
	esApiKey, err := createESApiKey(esClient)
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(esApiKey) > 1, "api key is invalid %q", esApiKey)

	apmArgs := []string{
		"run",
		"-e",
		"-E", "output.elasticsearch.hosts=['" + esHost + "']",
		"-E", "output.elasticsearch.api_key=" + esApiKey,
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
		fixture.RunWithClient(ctx, false)
		fixtureWg.Done()
	}()

	err = logWatcher.WaitForKeys(context.Background(),
		10*time.Minute,
		500*time.Millisecond,
		apmReadyLog,
	)
	require.NoError(t, err, "APM not initialized")
	fixture.WriteFileToWorkDir(ctx, apmProcessingContent, fileName)

	// check index
	var hits int
	match := map[string]interface{}{
		"labels.host_test-id": testId,
	}

	// apm mismatch or proper docs in ES
	err = logWatcher.WaitForKeys(context.Background(),
		20*time.Second,
		500*time.Millisecond,
		apmVersionMismatch)
	if err == nil {
		// err nil means there's a match within time limit
		// mark skipped to make it explicit it was not successfully evaluated
		t.Skip("agent version needs to be equal to stack version")
	} else {
		// failed to get APM version mismatch in time
		// processing should be running
		require.Eventually(t,
			func() bool {
				docs := findESDocs(t, func() (estools.Documents, error) {
					return estools.GetLogsForIndexWithContext(context.Background(), esClient, "logs-apm*", match)
				})
				hits = len(docs.Hits.Hits)
				return hits > 0
			},
			5*time.Minute, 500*time.Millisecond,
			"there should be apm logs by now")
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

func createESApiKey(esClient *elasticsearch.Client) (string, error) {
	apiResp, err := estools.CreateAPIKey(context.Background(), esClient, estools.APIKeyRequest{Name: "test-api-key", Expiration: "1d"})
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s", apiResp.Id, apiResp.APIKey), nil
}
