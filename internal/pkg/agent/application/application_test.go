// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
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
	storage, conf, err := mergeFleetConfig(context.Background(), rawConfig)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, conf)
	assert.Equal(t, conf.Fleet.Enabled, cfg["fleet"].(map[string]interface{})["enabled"])
	assert.Equal(t, conf.Fleet.AccessAPIKey, cfg["fleet"].(map[string]interface{})["access_api_key"])
	assert.Equal(t, conf.Settings.GRPC.Port, cfg["agent"].(map[string]interface{})["grpc"].(map[string]interface{})["port"].(uint16))
}

func TestLimitsLog(t *testing.T) {
	log, obs := logger.NewTesting("TestLimitsLog")
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
		false,             // not otel mode
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

func TestDeriveCommsSocketName(t *testing.T) {
	const controlAddressNix = "unix:///tmp/elastic-agent/pge4ao-u1YaV1dmSBfVX4saT8BL7b-Ey.sock"
	const controlAddressWin = "npipe:///_HZ8OL-9bNW-SIU0joRfgUsej2KX0Sra.sock"

	validControlAddress := func() string {
		if runtime.GOOS == "windows" {
			return controlAddressWin
		}
		return controlAddressNix
	}

	defaultCfg := configuration.DefaultGRPCConfig()

	tests := []struct {
		name           string
		controlAddress string
		local          bool
		wantErr        error
		want           string
	}{
		{
			name: "empty uri not local",
			want: defaultCfg.String(),
		},
		{
			name:    "empty uri local",
			local:   true,
			wantErr: errInvalidUri,
		},
		{
			name:           "invalid schema",
			controlAddress: "lunix:///2323",
			local:          true,
			wantErr:        errInvalidUri,
		},
		{
			name:           "valid schema empty path",
			controlAddress: "unix://",
			local:          true,
			wantErr:        errInvalidUri,
		},
		{
			name:           "valid path",
			controlAddress: validControlAddress(),
			local:          true,
			want:           validControlAddress(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Copy default config
			grpcCfg := *defaultCfg
			grpcCfg.Local = tc.local
			s, err := deriveCommsAddress(tc.controlAddress, &grpcCfg)

			// If want error, test error and return
			if tc.wantErr != nil {
				diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
				if diff != "" {
					t.Fatal(diff)
				}
				return
			}

			diff := cmp.Diff(len(tc.want), len(s))
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
