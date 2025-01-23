// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filesource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestContextProvider_Config(t *testing.T) {
	scenarios := []struct {
		Name   string
		Config *config.Config
		Err    error
	}{
		{
			Name: "no path",
			Config: config.MustNewConfigFrom(map[string]interface{}{
				"one": map[string]interface{}{},
			}),
			Err: errors.New(`"one" is missing a defined path`),
		},
		{
			Name: "invalid type",
			Config: config.MustNewConfigFrom(map[string]interface{}{
				"one": map[string]interface{}{
					"type": "json",
					"path": "/etc/agent/content",
				},
			}),
			Err: errors.New(`"one" defined an unsupported type "json"`),
		},
		// other errors in the config validation are hard to validate in a test
		// they are just very defensive
		{
			Name: "valid path",
			Config: config.MustNewConfigFrom(map[string]interface{}{
				"one": map[string]interface{}{
					"path": "/etc/agent/content1",
				},
				"two": map[string]interface{}{
					"path": "/etc/agent/content2",
				},
			}),
		},
	}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			log, err := logger.New("filesource_test", false)
			require.NoError(t, err)

			builder, _ := composable.Providers.GetContextProvider("filesource")
			_, err = builder(log, s.Config, true)
			if s.Err != nil {
				require.Equal(t, s.Err, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestContextProvider(t *testing.T) {
	const testTimeout = 1 * time.Second

	tmpDir := t.TempDir()
	value1 := "value1"
	file1 := filepath.Join(tmpDir, "value1_path")
	require.NoError(t, os.WriteFile(file1, []byte(value1), 0o644))
	value2 := "value2"
	file2 := filepath.Join(tmpDir, "value2_path")
	require.NoError(t, os.WriteFile(file2, []byte(value2), 0o644))

	log, err := logger.New("filesource_test", false)
	require.NoError(t, err)

	c, err := config.NewConfigFrom(map[string]interface{}{
		"one": map[string]interface{}{
			"path": file1,
		},
		"two": map[string]interface{}{
			"path": file2,
		},
	})
	require.NoError(t, err)
	builder, _ := composable.Providers.GetContextProvider("filesource")
	provider, err := builder(log, c, true)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)
	setChan := make(chan map[string]interface{})
	comm.CallOnSet(func(value map[string]interface{}) {
		// Forward Set's input to the test channel
		setChan <- value
	})

	go func() {
		_ = provider.Run(ctx, comm)
	}()

	// wait for it to be called once
	var current map[string]interface{}
	select {
	case current = <-setChan:
	case <-time.After(testTimeout):
		require.FailNow(t, "timeout waiting for provider to call Set")
	}

	require.Equal(t, value1, current["one"])
	require.Equal(t, value2, current["two"])

	// update the value in one
	value1 = "update1"
	require.NoError(t, os.WriteFile(file1, []byte(value1), 0o644))

	// wait for file1 to be updated
	var oneUpdated map[string]interface{}
	select {
	case oneUpdated = <-setChan:
	case <-time.After(testTimeout):
		require.FailNow(t, "timeout waiting for provider to call Set")
	}

	require.Equal(t, value1, oneUpdated["one"])
	require.Equal(t, value2, oneUpdated["two"])

	// update the value in two
	value2 = "update2"
	require.NoError(t, os.WriteFile(file2, []byte(value2), 0o644))

	// wait for file2 to be updated
	var twoUpdated map[string]interface{}
	select {
	case twoUpdated = <-setChan:
	case <-time.After(testTimeout):
		require.FailNow(t, "timeout waiting for provider to call Set")
	}

	require.Equal(t, value1, twoUpdated["one"])
	require.Equal(t, value2, twoUpdated["two"])
}
