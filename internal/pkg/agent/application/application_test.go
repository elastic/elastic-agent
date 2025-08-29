// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
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
	storage, conf, err := mergeFleetConfig(context.Background(), rawConfig)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, conf)
	assert.Equal(t, conf.Fleet.Enabled, cfg["fleet"].(map[string]interface{})["enabled"])
	assert.Equal(t, conf.Fleet.AccessAPIKey, cfg["fleet"].(map[string]interface{})["access_api_key"])
	assert.Equal(t, conf.Settings.GRPC.Port, cfg["agent"].(map[string]interface{})["grpc"].(map[string]interface{})["port"].(uint16))
}

func TestLimitsLog(t *testing.T) {
	log, obs := loggertest.New("TestLimitsLog")
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	_, _, _, err := New(
		ctx,
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{}, // info.AgentInfo
		nil,               // coordinator.ReExecManager
		nil,               // apm.Tracer
		true,              // testingMode
		time.Millisecond,  // fleetInitTimeout
		true,              // disable monitoring
		nil,               // no configuration overrides
		nil,
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

func TestInjectOutputOverrides(t *testing.T) {
	scenarios := []struct {
		Name         string
		RawConfig    map[string]any
		ChangeConfig map[string]any
		Result       map[string]any
	}{
		{
			Name: "rawConfig no outputs",
			RawConfig: map[string]any{
				"inputs": []any{},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
		},
		{
			Name: "change config no outputs",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			ChangeConfig: map[string]any{
				"inputs": []any{},
			},
			Result: map[string]any{
				"inputs": []any{},
			},
		},
		{
			Name: "mismatch output",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"elasticsearch": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"elasticsearch": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
		},
		{
			Name: "simple merge",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
		},
		{
			Name: "simple merge array",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-Other-Field": "field-123",
						},
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth":    "token-123",
							"X-Other-Field": "field-123",
						},
					},
				},
			},
		},
		{
			Name: "override setting from change",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Auth": "token-546",
						},
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Auth": "token-546",
						},
					},
				},
			},
		},
		{
			Name: "setting variables are not expanded",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "${filesource.app_token}",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Other": "${filesource.other_token}",
						},
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Auth":  "${filesource.app_token}",
							"X-App-Other": "${filesource.other_token}",
						},
					},
				},
			},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			log, _ := loggertest.New(t.Name())
			rawConfig := config.MustNewConfigFrom(scenario.RawConfig)
			cc := &mockConfigChange{c: config.MustNewConfigFrom(scenario.ChangeConfig)}
			observed := injectOutputOverrides(log, rawConfig)(cc).Config()
			observedMap, err := observed.ToMapStr()
			require.NoError(t, err)
			assert.Equal(t, scenario.Result, observedMap)
		})
	}
}
