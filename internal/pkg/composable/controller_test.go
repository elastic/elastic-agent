// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package composable_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, 1*time.Second)
	defer timeoutCancel()

	var setVars []*transpiler.Vars
	go func() {
		defer cancel()
		for {
			select {
			case <-timeoutCtx.Done():
				return
			case vars := <-c.Watch():
				setVars = vars
			}
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

	assert.Len(t, setVars, 3)

	_, hostExists := setVars[0].Lookup("host")
	assert.True(t, hostExists)
	_, envExists := setVars[0].Lookup("env")
	assert.False(t, envExists)
	local, _ := setVars[0].Lookup("local")
	localMap, ok := local.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value1", localMap["key1"])

	local, _ = setVars[1].Lookup("local_dynamic")
	localMap, ok = local.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value1", localMap["key1"])

	local, _ = setVars[2].Lookup("local_dynamic")
	localMap, ok = local.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value2", localMap["key1"])
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
			defer c.Close()

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
		defer c.Close()

		ctx, cancelFn := context.WithTimeout(context.Background(), 0)
		cancelFn()
		err = c.Run(ctx)
		// test will time out and fail if cancellation is not proper
		if err != nil {
			require.True(t, errors.Is(err, context.DeadlineExceeded))
		}
	})
}
