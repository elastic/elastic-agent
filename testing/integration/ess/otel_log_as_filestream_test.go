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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent-libs/testing/fs"
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

	rootDir, err := filepath.Abs(filepath.Join("..", "..", "..", "build"))
	require.NoError(t, err, "cannot get absolute path of rootDir")
	tmpDir := fs.TempDir(t, rootDir)
	agentLogFilePath := filepath.Join(tmpDir, "ea-log.ndjson")

	cfgFile := filepath.Join("testdata", "filebeat_receiver_log_as_filestream.yml")

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

	inputFilePath, err := filepath.Abs(filepath.Join(tmpDir, "log.log"))
	require.NoError(t, err, "cannot get absolute path of inputFilePath")

	// Generate a string we can use to search in the logs,
	// without it tests on Windows will fail
	inputFilePathStr := strings.ReplaceAll(inputFilePath, `\`, `\\`)

	WriteLogFile(t, inputFilePath, 50, false)

	esApiKey := createESApiKey(t, info.ESClient)
	esHost, err := integration.GetESHost()
	require.NoError(t, err, "failed to get ES host")

	cfg := map[string]any{
		"HomeDir":      tmpDir,
		"LogFilepath":  inputFilePath,
		"ESApiKey":     esApiKey.Encoded,
		"ESEndpoint":   esHost,
		"Namespace":    info.Namespace,
		"AsFilestream": false,
		"LogFolder":    agentLogFilePath,
	}

	fixture, err := define.NewFixtureFromLocalBuild(
		t,
		define.Version())
	require.NoError(t, err, "cannot create Elastic Agent fixture")

	yamlCfg := renderCfg(t, cfgFile, cfg)
	require.NoError(t, fixture.ConfigureOtel(t.Context(), yamlCfg), "cannot configure Otel")

	wg := sync.WaitGroup{}

	// Start Elastic Agent/Filebeat receiver running the Log input
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(3*time.Minute))
		defer cancel()
		require.NoError(t, fixture.RunOtelWithClient(ctx))
	}()

	agentLogFile := fs.LogFile{}
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		f, err := os.Open(agentLogFilePath)
		if err != nil {
			collect.Errorf("cannot open Elastic Agent log file for reading: %s", err)
			return
		}
		agentLogFile.File = f
		t.Cleanup(func() { f.Close() })
	}, 30*time.Second, 500*time.Millisecond, "cannot open Elastic Agent log file for reading")

	agentLogFile.WaitLogsContains(
		t,
		"Log input (deprecated) running as Log input (deprecated)",
		20*time.Second,
		"Log input did not start as Log input",
	)

	// Wait for all events to be ingested and stop Elastic Agent
	waitEventsInES(50)

	// Stop Elastic Agent
	fixture.Stop()
	wg.Wait()

	// Enable the feature flag and start Elastic Agent
	cfg["AsFilestream"] = true

	yamlCfg = renderCfg(t, cfgFile, cfg)
	require.NoError(t, fixture.ConfigureOtel(t.Context(), yamlCfg), "cannot configure Otel")

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
		defer cancel()
		require.NoError(t, fixture.RunOtelWithClient(ctx))
	}()

	// Ensure the Filestream input starts
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

	fixture.Stop()
	wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(3*
			time.Minute))
		defer cancel()
		require.NoError(t, fixture.RunOtelWithClient(ctx))
	}()

	// Start Elastic Agent again to ensure it is correctly tracking the state
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
	fixture.Stop()
	wg.Wait()

	// Ensure there was no data duplication
	waitEventsInES(100)
}

func renderCfg(t *testing.T, tmplFile string, cfg map[string]any) []byte {
	otelConfigBuffer := bytes.Buffer{}
	require.NoError(
		t,
		template.Must(template.ParseFiles(tmplFile)).Execute(&otelConfigBuffer, cfg),
		"cannot render template")
	return otelConfigBuffer.Bytes()
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
			t.Fatalf("could not write line %d to file: %s", i+1, err)
		}
	}
}
