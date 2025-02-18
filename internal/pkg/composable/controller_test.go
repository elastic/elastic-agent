// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composable_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/env"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/host"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/local"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/localdynamic"
)

func TestController(t *testing.T) {
	cfg, err := config.NewConfigFrom(map[string]interface{}{
		"providers": map[string]interface{}{
			"env": map[string]interface{}{
				"enabled": "false",
			},
			"local": map[string]interface{}{
				"vars": map[string]interface{}{
					"key1": "value1",
				},
			},
			"local_dynamic": map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"vars": map[string]interface{}{
							"key1": "value1",
						},
						"processors": []map[string]interface{}{
							{
								"add_fields": map[string]interface{}{
									"fields": map[string]interface{}{
										"add": "value1",
									},
									"to": "dynamic",
								},
							},
						},
					},
					{
						"vars": map[string]interface{}{
							"key1": "value2",
						},
						"processors": []map[string]interface{}{
							{
								"add_fields": map[string]interface{}{
									"fields": map[string]interface{}{
										"add": "value2",
									},
									"to": "dynamic",
								},
							},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	log, err := logger.New("", false)
	require.NoError(t, err)
	c, err := composable.New(log, cfg, false)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var setVars1 []*transpiler.Vars
	var setVars2 []*transpiler.Vars
	var setVars3 []*transpiler.Vars
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
			return
		case vars := <-c.Watch():
			// initial vars
			setVars1 = vars
			setVars2, err = c.Observe(ctx, []string{"local.vars.key1", "local_dynamic.vars.key1"}) // observed local and local_dynamic
			require.NoError(t, err)
			setVars3, err = c.Observe(ctx, nil) // no observed (will turn off those providers)
			require.NoError(t, err)
		}
	}()

	errCh := make(chan error)
	go func() {
		errCh <- c.Run(ctx)
	}()
	err = <-errCh
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	require.NoError(t, err)

	assert.Len(t, setVars1, 1)
	assert.Len(t, setVars2, 3)
	assert.Len(t, setVars3, 1)

	vars1map, err := setVars1[0].Map()
	require.NoError(t, err)
	assert.Len(t, vars1map, 0) // should be empty on initial

	_, hostExists := setVars2[0].Lookup("host")
	assert.False(t, hostExists) // should not exist, not referenced
	_, envExists := setVars2[0].Lookup("env")
	assert.False(t, envExists) // should not exist, not referenced
	local, _ := setVars2[0].Lookup("local")
	localMap, ok := local.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value1", localMap["key1"])

	local, _ = setVars2[1].Lookup("local_dynamic")
	localMap, ok = local.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value1", localMap["key1"])

	local, _ = setVars2[2].Lookup("local_dynamic")
	localMap, ok = local.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value2", localMap["key1"])

	vars3map, err := setVars3[0].Map()
	require.NoError(t, err)
	assert.Len(t, vars3map, 0) // should be empty after empty Observe
}

func TestProvidersDefaultDisabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      map[string]interface{}
		observed []string
		context  []string
		dynamic  []string
	}{
		{
			name: "default disabled",
			cfg: map[string]interface{}{
				"agent.providers.initial_default": "false",
			},
			observed: []string{"env.var1", "host.name"}, // has observed but explicitly disabled
			context:  nil,                               // should have none
		},
		{
			name: "default enabled",
			cfg: map[string]interface{}{
				"agent.providers.initial_default": "true",
			},
			observed: []string{"env.var1", "host.name"},
			context:  []string{"env", "host"},
		},
		{
			name:     "default enabled - no config",
			cfg:      map[string]interface{}{},
			observed: nil, // none observed
			context:  nil, // should have none
		},
		{
			name: "default enabled - explicit config",
			cfg: map[string]interface{}{
				"providers": map[string]interface{}{
					"env": map[string]interface{}{
						"enabled": "false",
					},
					"local": map[string]interface{}{
						"vars": map[string]interface{}{
							"key1": "value1",
						},
					},
					"local_dynamic": map[string]interface{}{
						"items": []map[string]interface{}{
							{
								"vars": map[string]interface{}{
									"key1": "value1",
								},
								"processors": []map[string]interface{}{
									{
										"add_fields": map[string]interface{}{
											"fields": map[string]interface{}{
												"add": "value1",
											},
											"to": "dynamic",
										},
									},
								},
							},
							{
								"vars": map[string]interface{}{
									"key1": "value2",
								},
								"processors": []map[string]interface{}{
									{
										"add_fields": map[string]interface{}{
											"fields": map[string]interface{}{
												"add": "value2",
											},
											"to": "dynamic",
										},
									},
								},
							},
						},
					},
				},
			},
			observed: []string{"local.vars.key1", "local_dynamic.vars.key1"},
			context:  []string{"local"},
			dynamic:  []string{"local_dynamic", "local_dynamic"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tt.cfg)
			require.NoError(t, err)

			log, err := logger.New("", false)
			require.NoError(t, err)
			c, err := composable.New(log, cfg, false)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			timeoutCtx, timeoutCancel := context.WithTimeout(ctx, 1*time.Second)
			defer timeoutCancel()

			errCh := make(chan error)
			go func() {
				errCh <- c.Run(ctx)
			}()

			var setVars []*transpiler.Vars
			go func() {
				defer cancel()

				observed := false
				for {
					select {
					case <-timeoutCtx.Done():
						return
					case vars := <-c.Watch():
						setVars = vars
					default:
						if !observed {
							vars, err := c.Observe(timeoutCtx, tt.observed)
							require.NoError(t, err)
							if vars != nil {
								setVars = vars
							}
							observed = true
						}
					}
				}
			}()

			err = <-errCh
			if errors.Is(err, context.Canceled) {
				err = nil
			}
			require.NoError(t, err)
			require.NotNil(t, setVars)

			if len(tt.context) > 0 {
				for _, name := range tt.context {
					_, ok := setVars[0].Lookup(name)
					assert.Truef(t, ok, "context vars group missing %s", name)
				}
			} else {
				m, err := setVars[0].Map()
				if assert.NoErrorf(t, err, "failed to convert context vars to map") {
					assert.Len(t, m, 0) // should be empty
				}
			}
			if len(tt.dynamic) > 0 {
				for i, name := range tt.dynamic {
					_, ok := setVars[i+1].Lookup(name)
					assert.Truef(t, ok, "dynamic vars group %d missing %s", i+1, name)
				}
			} else {
				// should not have any dynamic vars
				assert.Len(t, setVars, 1)
			}
		})
	}
}

func TestCancellation(t *testing.T) {
	cfg, err := config.NewConfigFrom(map[string]interface{}{
		"providers": map[string]interface{}{
			"env": map[string]interface{}{
				"enabled": "false",
			},
			"local": map[string]interface{}{
				"vars": map[string]interface{}{
					"key1": "value1",
				},
			},
			"local_dynamic": map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"vars": map[string]interface{}{
							"key1": "value1",
						},
						"processors": []map[string]interface{}{
							{
								"add_fields": map[string]interface{}{
									"fields": map[string]interface{}{
										"add": "value1",
									},
									"to": "dynamic",
								},
							},
						},
					},
					{
						"vars": map[string]interface{}{
							"key1": "value2",
						},
						"processors": []map[string]interface{}{
							{
								"add_fields": map[string]interface{}{
									"fields": map[string]interface{}{
										"add": "value2",
									},
									"to": "dynamic",
								},
							},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	log, err := logger.New("", false)
	require.NoError(t, err)

	// try with variable deadlines
	timeout := 50 * time.Millisecond
	for i := 1; i <= 10; i++ {
		t.Run(fmt.Sprintf("test run %d", i), func(t *testing.T) {
			c, err := composable.New(log, cfg, false)
			require.NoError(t, err)

			ctx, cancelFn := context.WithTimeout(context.Background(), timeout)
			defer cancelFn()
			err = c.Run(ctx)
			// test will time out and fail if cancellation is not proper
			if err != nil {
				require.True(t, errors.Is(err, context.DeadlineExceeded))
			}
		})
		timeout += 10 * time.Millisecond
	}

	t.Run("immediate cancellation", func(t *testing.T) {
		c, err := composable.New(log, cfg, false)
		require.NoError(t, err)

		ctx, cancelFn := context.WithTimeout(context.Background(), 0)
		cancelFn()
		err = c.Run(ctx)
		// test will time out and fail if cancellation is not proper
		if err != nil {
			require.True(t, errors.Is(err, context.DeadlineExceeded))
		}
	})
}

func TestDefaultProvider(t *testing.T) {
	log, err := logger.New("", false)
	require.NoError(t, err)

	t.Run("default env", func(t *testing.T) {
		c, err := composable.New(log, nil, false)
		require.NoError(t, err)
		assert.Equal(t, "env", c.DefaultProvider())
	})

	t.Run("no default", func(t *testing.T) {
		cfg, err := config.NewConfigFrom(map[string]interface{}{
			"agent.providers.default": "",
		})
		require.NoError(t, err)
		c, err := composable.New(log, cfg, false)
		require.NoError(t, err)
		assert.Equal(t, "", c.DefaultProvider())
	})

	t.Run("custom default", func(t *testing.T) {
		cfg, err := config.NewConfigFrom(map[string]interface{}{
			"agent.providers.default": "custom",
		})
		require.NoError(t, err)
		c, err := composable.New(log, cfg, false)
		require.NoError(t, err)
		assert.Equal(t, "custom", c.DefaultProvider())
	})
}
