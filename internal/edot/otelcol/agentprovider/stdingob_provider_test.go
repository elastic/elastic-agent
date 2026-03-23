// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"context"
	"encoding/gob"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v3"
)

const testStdinGobURI = StdinGobProviderSchemeName + ":stdin"

// encodeYAMLBytesGob marshals config to YAML and encodes the bytes using gob.
func encodeYAMLBytesGob(encoder *gob.Encoder, cfg map[string]any) error {
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return encoder.Encode(yamlBytes)
}

// newTestStdinGobProvider creates a StdinGobProvider backed by an io.Pipe().
// It returns the provider and the write end of the pipe (for writing configs).
func newTestStdinGobProvider(t *testing.T) (confmap.Provider, io.WriteCloser) {
	t.Helper()

	pipeReader, pipeWriter := io.Pipe()
	factory := NewStdinGobFactoryWithReader(pipeReader)
	provider := factory.Create(confmap.ProviderSettings{})
	t.Cleanup(func() {
		assert.NoError(t, pipeWriter.Close())
	})
	return provider, pipeWriter
}

func TestStdinGobProvider_Scheme(t *testing.T) {
	p, pipeWriter := newTestStdinGobProvider(t)
	defer pipeWriter.Close()
	assert.Equal(t, StdinGobProviderSchemeName, p.Scheme())
}

func TestStdinGobProvider_InitialConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)
	encoder := gob.NewEncoder(pipeWriter)

	cfg := map[string]any{"receivers": map[string]any{"otlp": map[string]any{}}}

	// Write initial config before Retrieve
	go func() {
		_ = encodeYAMLBytesGob(encoder, cfg)
	}()

	ret, err := p.Retrieve(ctx, testStdinGobURI, func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ret.Close(ctx))
	})

	retCfg, err := ret.AsConf()
	require.NoError(t, err)

	// Verify the config was read correctly
	assert.NotNil(t, retCfg.Get("receivers"))

	pipeWriter.Close()
	require.NoError(t, p.Shutdown(ctx))
}

func TestStdinGobProvider_ConfigUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)
	encoder := gob.NewEncoder(pipeWriter)

	initialCfg := map[string]any{"version": "1"}
	updatedCfg := map[string]any{"version": "2"}

	// Write initial config
	go func() {
		require.NoError(t, encodeYAMLBytesGob(encoder, initialCfg))
	}()

	watcherCalled := make(chan struct{})
	ret, err := p.Retrieve(ctx, testStdinGobURI, func(event *confmap.ChangeEvent) {
		close(watcherCalled)
	})
	require.NoError(t, err)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "1", retCfg.Get("version"))

	go func() {
		require.NoError(t, encodeYAMLBytesGob(encoder, updatedCfg))
	}()

	// Wait for watcher to be called
	select {
	case <-watcherCalled:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for watcher to be called")
	}

	// Close first retrieval
	require.NoError(t, ret.Close(ctx))

	// Retrieve again to get the updated config
	ret2, err := p.Retrieve(ctx, testStdinGobURI, nil)
	require.NoError(t, err)
	require.NoError(t, ret2.Close(ctx))

	retCfg2, err := ret2.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "2", retCfg2.Get("version"))

	// Clean up
	require.NoError(t, p.Shutdown(ctx))
}

func TestStdinGobProvider_MultipleUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)
	encoder := gob.NewEncoder(pipeWriter)

	// Write initial config
	go func() {
		require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{"count": 0}))
	}()

	watcherCalled := make(chan struct{}, 10)

	ret, err := p.Retrieve(ctx, testStdinGobURI, func(event *confmap.ChangeEvent) {
		watcherCalled <- struct{}{}
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ret.Close(ctx))
	})

	// Write multiple updates
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 3 {
			require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{"count": i}))
		}
	}()
	t.Cleanup(wg.Wait)

	// Wait for at least one watcher call
	select {
	case <-watcherCalled:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for watcher to be called")
	}
}

func TestStdinGobProvider_PipeCloseIsNotAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)
	encoder := gob.NewEncoder(pipeWriter)

	// Write initial config then signal ready
	go func() {
		require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{"key": "value"}))
	}()

	watcherCalled := make(chan *confmap.ChangeEvent, 1)
	ret, err := p.Retrieve(ctx, testStdinGobURI, func(event *confmap.ChangeEvent) {
		watcherCalled <- event
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ret.Close(ctx))
	})

	// Close the pipe — the background reader should exit silently
	// (EOF is not an error) and the watcher should NOT be called.
	require.NoError(t, pipeWriter.Close())

	select {
	case <-watcherCalled:
		t.Fatal("watcher should not be called on EOF")
	case <-time.After(200 * time.Millisecond):
		// Success — no watcher call.
	}

	// The last config should still be retrievable.
	ret2, err := p.Retrieve(ctx, testStdinGobURI, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ret2.Close(ctx))
	})
	retCfg, err := ret2.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "value", retCfg.Get("key"))
}

func TestStdinGobProvider_Shutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)

	// Write initial config
	go func() {
		encoder := gob.NewEncoder(pipeWriter)
		require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{"key": "value"}))
		// Keep pipe open so background reader is blocking
	}()

	ret, err := p.Retrieve(ctx, testStdinGobURI, func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	require.NoError(t, ret.Close(ctx))

	// Shutdown should succeed and close the reader
	require.NoError(t, p.Shutdown(ctx))
}

func TestStdinGobProvider_RetrievedClose(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)
	encoder := gob.NewEncoder(pipeWriter)

	// Write initial config
	go func() {
		require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{"key": "value"}))
	}()

	watcherCalled := make(chan struct{})
	ret, err := p.Retrieve(ctx, testStdinGobURI, func(event *confmap.ChangeEvent) {
		close(watcherCalled)
	})
	require.NoError(t, err)

	// Close the retrieved - this should stop the watcher
	require.NoError(t, ret.Close(ctx))

	// Write another config - watcher should NOT be called since we closed
	go func() {
		require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{"key": "value2"}))
	}()

	// Give some time for the watcher to potentially be called
	select {
	case <-watcherCalled:
		t.Fatal("watcher was called after Close")
	case <-time.After(100 * time.Millisecond):
		// Success - watcher was not called
	}

	require.NoError(t, p.Shutdown(ctx))
}

func TestStdinGobProvider_EmptyConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)
	encoder := gob.NewEncoder(pipeWriter)

	go func() {
		require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{}))
	}()

	ret, err := p.Retrieve(ctx, testStdinGobURI, func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ret.Close(ctx))
	})

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Empty(t, retCfg.AllKeys())

	require.NoError(t, p.Shutdown(ctx))
}

func TestStdinGobProvider_InvalidGobData(t *testing.T) {
	p, pipeWriter := newTestStdinGobProvider(t)

	// Write invalid gob data directly to the pipe
	go func() {
		_, err := pipeWriter.Write([]byte{0, 0})
		require.NoError(t, err)
	}()

	// Error should occur on Retrieve during initial config read
	_, err := p.Retrieve(t.Context(), testStdinGobURI, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode config")
}

func TestStdinGobProvider_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, pipeReader.Close())
		assert.NoError(t, pipeWriter.Close())
	})

	factory := NewStdinGobFactoryWithReader(pipeReader)
	p := factory.Create(confmap.ProviderSettings{})

	// Retrieve should fail immediately with cancelled context
	_, err := p.Retrieve(ctx, testStdinGobURI, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestStdinGobProvider_NilWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p, pipeWriter := newTestStdinGobProvider(t)
	t.Cleanup(func() {
		assert.NoError(t, pipeWriter.Close())
	})

	go func() {
		encoder := gob.NewEncoder(pipeWriter)
		require.NoError(t, encodeYAMLBytesGob(encoder, map[string]any{"key": "value"}))
	}()

	// Should work fine with nil watcher
	ret, err := p.Retrieve(ctx, testStdinGobURI, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ret.Close(ctx))
	})

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "value", retCfg.Get("key"))

	require.NoError(t, p.Shutdown(ctx))
}
