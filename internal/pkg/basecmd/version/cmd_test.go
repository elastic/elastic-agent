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

package version

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/control/server"
	"github.com/elastic/elastic-agent-poc/internal/pkg/cli"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/release"
)

func TestCmdBinaryOnly(t *testing.T) {
	streams, _, out, _ := cli.NewTestingIOStreams()
	cmd := NewCommandWithArgs(streams)
	cmd.Flags().Set("binary-only", "true")
	err := cmd.Execute()
	require.NoError(t, err)
	version, err := ioutil.ReadAll(out)

	require.NoError(t, err)
	assert.True(t, strings.Contains(string(version), "Binary: "))
	assert.False(t, strings.Contains(string(version), "Daemon: "))
}

func TestCmdBinaryOnlyYAML(t *testing.T) {
	streams, _, out, _ := cli.NewTestingIOStreams()
	cmd := NewCommandWithArgs(streams)
	cmd.Flags().Set("binary-only", "true")
	cmd.Flags().Set("yaml", "true")
	err := cmd.Execute()
	require.NoError(t, err)
	version, err := ioutil.ReadAll(out)

	require.NoError(t, err)

	var output Output
	err = yaml.Unmarshal(version, &output)
	require.NoError(t, err)

	assert.Nil(t, output.Daemon)
	assert.Equal(t, release.Info(), *output.Binary)
}

func TestCmdDaemon(t *testing.T) {
	srv := server.New(newErrorLogger(t), nil, nil, nil)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	streams, _, out, _ := cli.NewTestingIOStreams()
	cmd := NewCommandWithArgs(streams)
	err := cmd.Execute()
	require.NoError(t, err)
	version, err := ioutil.ReadAll(out)

	require.NoError(t, err)
	assert.True(t, strings.Contains(string(version), "Binary: "))
	assert.True(t, strings.Contains(string(version), "Daemon: "))
}

func TestCmdDaemonYAML(t *testing.T) {
	srv := server.New(newErrorLogger(t), nil, nil, nil)
	require.NoError(t, srv.Start())
	defer srv.Stop()

	streams, _, out, _ := cli.NewTestingIOStreams()
	cmd := NewCommandWithArgs(streams)
	cmd.Flags().Set("yaml", "true")
	err := cmd.Execute()
	require.NoError(t, err)
	version, err := ioutil.ReadAll(out)

	require.NoError(t, err)

	var output Output
	err = yaml.Unmarshal(version, &output)
	require.NoError(t, err)

	assert.Equal(t, release.Info(), *output.Daemon)
	assert.Equal(t, release.Info(), *output.Binary)
}

func TestCmdDaemonErr(t *testing.T) {
	// srv not started
	streams, _, out, _ := cli.NewTestingIOStreams()
	cmd := NewCommandWithArgs(streams)
	err := cmd.Execute()
	require.Error(t, err)
	version, err := ioutil.ReadAll(out)
	require.NoError(t, err)

	assert.True(t, strings.Contains(string(version), "Binary: "))
	assert.True(t, strings.Contains(string(version), "Daemon: "))
}

func TestCmdDaemonErrYAML(t *testing.T) {
	// srv not started
	streams, _, out, _ := cli.NewTestingIOStreams()
	cmd := NewCommandWithArgs(streams)
	cmd.Flags().Set("yaml", "true")
	err := cmd.Execute()
	require.Error(t, err)
	version, err := ioutil.ReadAll(out)

	require.NoError(t, err)
	var output Output
	err = yaml.Unmarshal(version, &output)
	require.NoError(t, err)

	assert.Nil(t, output.Daemon)
	assert.Equal(t, release.Info(), *output.Binary)
}

func newErrorLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.ErrorLevel

	log, err := logger.NewFromConfig("", loggerCfg, false)
	require.NoError(t, err)
	return log
}
