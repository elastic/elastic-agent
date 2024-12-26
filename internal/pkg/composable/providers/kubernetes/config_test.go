// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestGetHintsInputConfigPath(t *testing.T) {

	log, err := logger.New("loader_test", true)
	require.NoError(t, err, "failed to create logger ", err)

	for _, tc := range []struct {
		name         string
		cfg          map[string]any
		expectedPath string
	}{
		{
			name: "fully composite yaml key",
			cfg: map[string]any{
				"providers.kubernetes.hints.enabled": true,
			},
			expectedPath: hintsInputsPathPattern,
		},
		{
			name: "partially composite yaml key",
			cfg: map[string]any{
				"providers.kubernetes": map[string]any{
					"hints.enabled": false,
				},
			},
			expectedPath: "",
		},
		{
			name: "normal yaml key",
			cfg: map[string]any{
				"providers": map[string]any{
					"kubernetes": map[string]any{
						"hints": map[string]any{
							"enabled": true,
						},
					},
				},
			},
			expectedPath: hintsInputsPathPattern,
		},
		{
			name: "hints enabled no bool",
			cfg: map[string]any{
				"providers": map[string]any{
					"kubernetes": map[string]any{
						"hints": map[string]any{
							"enabled": "true",
						},
					},
				},
			},
			expectedPath: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tc.cfg)
			require.NoError(t, err)

			mapCfg, err := cfg.ToMapStr()
			require.NoError(t, err)

			require.Equal(t, tc.expectedPath, GetHintsInputConfigPath(log, mapCfg))
		})
	}

}
