// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package control_test

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent-poc/internal/pkg/core/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/control/server"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/release"
)

func TestServerClient_Version(t *testing.T) {
	srv := server.New(newErrorLogger(t), nil, nil, nil)
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

func TestServerClient_Status(t *testing.T) {
	l := newErrorLogger(t)
	statusCtrl := status.NewController(l)
	srv := server.New(l, nil, statusCtrl, nil)
	err := srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	c := client.New()
	err = c.Connect(context.Background())
	require.NoError(t, err)
	defer c.Disconnect()

	status, err := c.Status(context.Background())
	require.NoError(t, err)

	assert.Equal(t, &client.AgentStatus{
		Status:       client.Healthy,
		Message:      "",
		Applications: []*client.ApplicationStatus{},
	}, status)
}

func newErrorLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.ErrorLevel

	log, err := logger.NewFromConfig("", loggerCfg, false)
	require.NoError(t, err)
	return log
}
