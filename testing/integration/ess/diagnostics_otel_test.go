// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestEDOTDiagnostics(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: false,
	})

	configTemplate := `
inputs:
  - id: filestream-filebeat
    type: filestream
    paths:
      - {{ .InputFile }}
    prospector.scanner.fingerprint.enabled: false
    file_identity.native: ~
    use_output: default
    _runtime_experimental: otel
agent.grpc:
    port: 6790
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
agent.monitoring.enabled: false
`

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Create the fixture
	f, err := define.NewFixtureFromLocalBuild(t, define.Version(), integrationtest.WithAllowErrors())
	require.NoError(t, err)

	// Create the data file to ingest
	inputFile, err := os.CreateTemp(t.TempDir(), "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	t.Cleanup(func() {
		cErr := inputFile.Close()
		assert.NoError(t, cErr)
	})
	_, err = inputFile.WriteString("hello world\n")
	require.NoError(t, err, "failed to write data to temp file")

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer, map[string]any{
			"InputFile": inputFile.Name(),
		}))
	err = f.Prepare(ctx)
	require.NoError(t, err)

	err = f.Configure(ctx, configBuffer.Bytes())
	require.NoError(t, err)
	cmd, err := f.PrepareAgentCommand(ctx, []string{"-e"})
	require.NoError(t, err)

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	err = cmd.Start()
	require.NoError(t, err)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		err = f.IsHealthy(ctx)
		require.NoErrorf(collect, err, "agent is not healthy: %s", err)
		require.Containsf(collect, output.String(), "Diagnostics extension started", "expected log: %s", output.String())
	}, 30*time.Second, 1*time.Second)

	diagZip, err := f.ExecDiagnostics(ctx)
	extractionDir := t.TempDir()

	stat, err := os.Stat(diagZip)
	require.NoErrorf(t, err, "stat file %q failed", diagZip)
	require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", diagZip)

	extractZipArchive(t, diagZip, extractionDir)

	expectedFiles := []string{
		"edot/otel-merged-actual.yaml",
		"edot/allocs.profile.gz",
		"edot/block.profile.gz",
		"edot/goroutine.profile.gz",
		"edot/heap.profile.gz",
		"edot/mutex.profile.gz",
		"edot/threadcreate.profile.gz",
	}

	for _, f := range expectedFiles {
		path := filepath.Join(extractionDir, f)
		stat, err := os.Stat(path)
		require.NoErrorf(t, err, "stat file %q failed", path)
		require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", path)
	}
}
