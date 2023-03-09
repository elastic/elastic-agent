// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package v1_test

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/server"

	"go.elastic.co/apm/apmtest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestServerClient_Version(t *testing.T) {
	srv := server.New(newErrorLogger(t), nil, nil, apmtest.DiscardTracer, nil, configuration.DefaultGRPCConfig())
	err := srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	c := client.New()
	err = c.Connect(context.Background())
	require.NoError(t, err)
	defer c.Disconnect()

	ver, err := c.Version(context.Background())
	require.NoError(t, err)

	assert.Equal(t, client.Version{
		Version:   release.Version(),
		Commit:    release.Commit(),
		BuildTime: release.BuildTime(),
		Snapshot:  release.Snapshot(),
	}, ver)
}

func newErrorLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.ErrorLevel

	log, err := logger.NewFromConfig("", loggerCfg, false)
	require.NoError(t, err)
	return log
}
