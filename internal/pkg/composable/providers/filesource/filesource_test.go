// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filesource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
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
				"sources": map[string]interface{}{
					"one": map[string]interface{}{},
				},
			}),
			Err: errors.New(`"one" is missing a defined path`),
		},
		{
			Name: "invalid type",
			Config: config.MustNewConfigFrom(map[string]interface{}{
				"sources": map[string]interface{}{
					"one": map[string]interface{}{
						"type": "json",
						"path": "/etc/agent/content",
					},
				},
			}),
			Err: errors.New(`"one" defined an unsupported type "json"`),
		},
		// other errors in the config validation are hard to validate in a test
		// they are just very defensive
		{
			Name: "valid path",
			Config: config.MustNewConfigFrom(map[string]interface{}{
				"sources": map[string]interface{}{
					"one": map[string]interface{}{
						"path": "/etc/agent/content1",
					},
					"two": map[string]interface{}{
						"path": "/etc/agent/content2",
					},
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
	const testTimeout = 3 * time.Second

	tmpDir := t.TempDir()
	value1 := "value1"
	file1 := filepath.Join(tmpDir, "vAlUe1_path")
	require.NoError(t, os.WriteFile(file1, []byte(value1), 0o644))
	value2 := "value2"
	file2 := filepath.Join(tmpDir, "vAlUe2_path")
	require.NoError(t, os.WriteFile(file2, []byte(value2), 0o644))

	log, err := logger.New("filesource_test", false)
	require.NoError(t, err)

	osPath := func(path string) string {
		return path
	}
	if runtime.GOOS == "windows" {
		// on Windows configure the path as lower case even though it
		// is written as non-lower case to ensure that on Windows the
		// filewatcher observes the correct path
		osPath = func(path string) string {
			return strings.ToLower(path)
		}
	}
	c, err := config.NewConfigFrom(map[string]interface{}{
		"sources": map[string]interface{}{
			"one": map[string]interface{}{
				"path": osPath(file1),
			},
			"two": map[string]interface{}{
				"path": osPath(file2),
			},
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
	for {
		var oneUpdated map[string]interface{}
		select {
		case oneUpdated = <-setChan:
		case <-time.After(testTimeout):
			require.FailNow(t, "timeout waiting for provider to call Set")
		}

		if value1 == oneUpdated["one"] && value2 == oneUpdated["two"] {
			break
		}
	}

	// update the value in two
	value2 = "update2"
	require.NoError(t, os.WriteFile(file2, []byte(value2), 0o644))

	for {
		// wait for file2 to be updated
		var twoUpdated map[string]interface{}
		select {
		case twoUpdated = <-setChan:
		case <-time.After(testTimeout):
			require.FailNow(t, "timeout waiting for provider to call Set")
		}

		if value1 == twoUpdated["one"] && value2 == twoUpdated["two"] {
			break
		}
	}
}

func TestContextProvider_KubernetesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Kubernetes symlink test on Windows, because atomic replacing a symlink using os.Rename doesn't work")
	}

	const testTimeout = 3 * time.Second

	// Create directory structure that mimics Kubernetes secrets
	tmpDir := t.TempDir()

	// Create initial timestamped directory with secret content
	dataDir1 := filepath.Join(tmpDir, "..2024_01_01_12_00")
	require.NoError(t, os.Mkdir(dataDir1, 0o755))

	value1 := "secret-token-v1"
	tokenFile1 := filepath.Join(dataDir1, "token")
	require.NoError(t, os.WriteFile(tokenFile1, []byte(value1), 0o644))

	value2 := "secret-cert-v1"
	certFile1 := filepath.Join(dataDir1, "ca.crt")
	require.NoError(t, os.WriteFile(certFile1, []byte(value2), 0o644))

	// Create ..data symlink pointing to the timestamped directory
	dataSymlink := filepath.Join(tmpDir, "..data")
	require.NoError(t, os.Symlink(dataDir1, dataSymlink))

	// Create top-level symlinks (what the user actually references)
	tokenSymlink := filepath.Join(tmpDir, "token")
	require.NoError(t, os.Symlink(filepath.Join("..data", "token"), tokenSymlink))

	certSymlink := filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.Symlink(filepath.Join("..data", "ca.crt"), certSymlink))

	// Setup logger and provider
	log, err := logger.New("filesource_test", false)
	require.NoError(t, err)

	osPath := func(path string) string {
		return path
	}
	if runtime.GOOS == "windows" {
		osPath = func(path string) string {
			return strings.ToLower(path)
		}
	}

	c, err := config.NewConfigFrom(map[string]interface{}{
		"sources": map[string]interface{}{
			"token": map[string]interface{}{
				"path": osPath(tokenSymlink),
			},
			"cert": map[string]interface{}{
				"path": osPath(certSymlink),
			},
		},
	})
	require.NoError(t, err)

	builder, _ := composable.Providers.GetContextProvider("filesource")
	provider, err := builder(log, c, true)
	require.NoError(t, err)

	ctx := t.Context()
	comm := ctesting.NewContextComm(ctx)
	setChan := make(chan map[string]interface{})
	comm.CallOnSet(func(value map[string]interface{}) {
		t.Logf("Set called with: token=%v, cert=%v", value["token"], value["cert"])
		setChan <- value
	})

	// the provider can write to the comm, which logs to the test context
	// because of this, we need to wait for it to exit before the test concludes
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		_ = provider.Run(ctx, comm)
		wg.Done()
	}()
	t.Cleanup(func() { wg.Wait() })

	// Wait for initial values
	var current map[string]interface{}
	select {
	case current = <-setChan:
	case <-time.After(testTimeout):
		require.FailNow(t, "timeout waiting for provider to call Set")
	}

	require.Equal(t, value1, current["token"], "initial token value should match")
	require.Equal(t, value2, current["cert"], "initial cert value should match")

	// Simulate Kubernetes secret update:
	// 1. Create new timestamped directory with updated content
	dataDir2 := filepath.Join(tmpDir, "..2024_01_01_13_00")
	require.NoError(t, os.Mkdir(dataDir2, 0o755))

	value1Updated := "secret-token-v2"
	tokenFile2 := filepath.Join(dataDir2, "token")
	require.NoError(t, os.WriteFile(tokenFile2, []byte(value1Updated), 0o644))

	value2Updated := "secret-cert-v2"
	certFile2 := filepath.Join(dataDir2, "ca.crt")
	require.NoError(t, os.WriteFile(certFile2, []byte(value2Updated), 0o644))

	// 2. Atomically replace ..data symlink (this is what Kubernetes does)
	// Create temporary symlink, then rename it to replace the old one atomically
	dataTmpSymlink := filepath.Join(tmpDir, "..data_tmp")
	require.NoError(t, os.Symlink(dataDir2, dataTmpSymlink))
	require.NoError(t, os.Rename(dataTmpSymlink, dataSymlink))

	// Note: The top-level symlinks (token, ca.crt) are NOT modified
	// They still point to ..data/token and ..data/ca.crt
	// Only the ..data symlink target changed

	// Wait for the provider to detect the update
	// This should happen because fsnotify should see the ..data symlink change
	updateDetected := false
	deadline := time.After(testTimeout)
	for !updateDetected {
		select {
		case updated := <-setChan:
			// Check if we got the updated values
			if updated["token"] == value1Updated && updated["cert"] == value2Updated {
				updateDetected = true
				t.Log("Successfully detected Kubernetes-style symlink update")
			} else {
				t.Logf("Got update but values don't match yet: token=%v, cert=%v", updated["token"], updated["cert"])
			}
		case <-deadline:
			require.FailNow(t, "timeout waiting for provider to detect Kubernetes-style symlink update")
		}
	}

	require.True(t, updateDetected, "provider should detect Kubernetes-style symlink updates")
}
