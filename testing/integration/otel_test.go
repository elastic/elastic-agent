// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/stretchr/testify/require"
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

func TestFileProcessing(t *testing.T) {
	define.Require(t, define.Requirements{
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

	ctx, cancel := context.WithCancel(context.Background())
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
		err = fixture.RunWithClient(ctx, false)
		fixtureWg.Done()
	}()
	// agent does not communicate status when running in otel mode
	// we need to wait for processing to happen
	<-time.After(20 * time.Second)

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded, "Retrieved unexpected error: %s", err.Error())

	// verify file exists
	content, err := os.ReadFile(fileProcessingFilename)
	require.NoError(t, err)
	require.True(t, len(content) > 0)
}
