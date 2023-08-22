// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/limits"
)

func TestMergeFleetConfig(t *testing.T) {
	testutils.InitStorage(t)

	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"enabled":        true,
			"kibana":         map[string]interface{}{"host": "demo"},
			"access_api_key": "123",
		},
		"agent": map[string]interface{}{
			"grpc": map[string]interface{}{
				"port": uint16(6790),
			},
		},
	}

	rawConfig := config.MustNewConfigFrom(cfg)
	storage, conf, err := mergeFleetConfig(rawConfig)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, conf)
	assert.Equal(t, conf.Fleet.Enabled, cfg["fleet"].(map[string]interface{})["enabled"])
	assert.Equal(t, conf.Fleet.AccessAPIKey, cfg["fleet"].(map[string]interface{})["access_api_key"])
	assert.Equal(t, conf.Settings.GRPC.Port, cfg["agent"].(map[string]interface{})["grpc"].(map[string]interface{})["port"].(uint16))
}

func TestLimitsLog(t *testing.T) {
	log, obs := logger.NewTesting("TestLimitsLog")
	_, _, _, err := New(
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{}, // info.AgentInfo
		nil,               // coordinator.ReExecManager
		nil,               // apm.Tracer
		true,              // testingMode
		time.Millisecond,  // fleetInitTimeout
		true,              // disable monitoring
	)
	require.NoError(t, err)

	old := limits.LimitsConfig{
		GoMaxProcs: 0,
	}
	new := limits.LimitsConfig{
		GoMaxProcs: 99,
	}

	// apply is also called inside `New`, however there is no log line because the config file
	// does not define `agent.limits.go_max_procs` and the default value does not change.
	// so, no callback, no log line.

	// now we trigger the log line
	err = limits.Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 99`))
	require.NoError(t, err)

	expLogLine := fmt.Sprintf("agent limits have changed: %+v -> %+v", old, new)
	logs := obs.FilterMessageSnippet(expLogLine)
	require.Equalf(t, 1, logs.Len(), "expected one log message about limits change")
}
