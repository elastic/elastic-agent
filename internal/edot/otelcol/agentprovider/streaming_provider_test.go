// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"bytes"
	"context"
	"encoding/gob"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v2"
)

// encodeConfigToBuffer marshals config to YAML and encodes the bytes using gob into a buffer
func encodeConfigToBuffer(cfg map[string]any) *bytes.Buffer {
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	_ = encoder.Encode(yamlBytes)
	return &buf
}

// encodeYAMLBytes encodes YAML bytes using gob to the given encoder
func encodeYAMLBytes(encoder *gob.Encoder, cfg map[string]any) error {
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return encoder.Encode(yamlBytes)
}

func TestStreamingProvider_NewFactory(t *testing.T) {
	buf := encodeConfigToBuffer(map[string]any{"key": "value"})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)
	assert.Equal(t, p, p.NewFactory().Create(confmap.ProviderSettings{}))
}

func TestStreamingProvider_Schema(t *testing.T) {
	buf := encodeConfigToBuffer(map[string]any{"key": "value"})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)
	assert.Equal(t, AgentConfigProviderSchemeName, p.Scheme())
}

func TestStreamingProvider_URI(t *testing.T) {
	buf := encodeConfigToBuffer(map[string]any{"key": "value"})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)
	assert.Equal(t, p.uri, p.URI())
}

func TestStreamingProvider_InitialConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := map[string]any{"receivers": map[string]any{"otlp": map[string]any{}}}
	buf := encodeConfigToBuffer(cfg)

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)

	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	defer ret.Close(ctx)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)

	// Verify the config was read correctly
	assert.NotNil(t, retCfg.Get("receivers"))
}

func TestStreamingProvider_ConfigUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initialCfg := map[string]any{"version": "1"}
	updatedCfg := map[string]any{"version": "2"}

	reader, writer := io.Pipe()
	readyCh := make(chan *gob.Encoder)
	configWritten := make(chan struct{})

	// Use a single encoder for the entire stream
	go func() {
		encoder := gob.NewEncoder(writer)
		_ = encodeYAMLBytes(encoder, initialCfg)
		// Signal that encoder is ready for more writes
		readyCh <- encoder
	}()

	p, err := NewStreamingProvider(reader)
	require.NoError(t, err)

	watcherCalled := make(chan struct{})
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {
		close(watcherCalled)
	})
	require.NoError(t, err)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "1", retCfg.Get("version"))

	// Get the encoder and write updated config
	encoder := <-readyCh
	go func() {
		_ = encodeYAMLBytes(encoder, updatedCfg)
		close(configWritten)
		// Don't close writer yet - keep stream open
	}()

	// Wait for watcher to be called
	select {
	case <-watcherCalled:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for watcher to be called")
	}

	// Wait for config to be written
	<-configWritten

	// Close first retrieval
	ret.Close(ctx)

	// Retrieve again to get the updated config
	ret2, err := p.Retrieve(ctx, p.URI(), nil)
	require.NoError(t, err)
	defer ret2.Close(ctx)

	retCfg2, err := ret2.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "2", retCfg2.Get("version"))

	// Clean up
	writer.Close()
	p.Shutdown(ctx)
}

func TestStreamingProvider_MultipleUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, writer := io.Pipe()
	readyCh := make(chan *gob.Encoder)

	// Use a single encoder for the entire stream
	go func() {
		encoder := gob.NewEncoder(writer)
		_ = encodeYAMLBytes(encoder, map[string]any{"count": 0})
		readyCh <- encoder
	}()

	p, err := NewStreamingProvider(reader)
	require.NoError(t, err)

	// Track watcher calls
	var watcherCallCount int
	var watcherMu sync.Mutex
	watcherCalled := make(chan struct{}, 10)

	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {
		watcherMu.Lock()
		watcherCallCount++
		watcherMu.Unlock()
		watcherCalled <- struct{}{}
	})
	require.NoError(t, err)
	defer ret.Close(ctx)

	// Get encoder and write multiple updates
	encoder := <-readyCh
	go func() {
		for i := 1; i <= 3; i++ {
			_ = encodeYAMLBytes(encoder, map[string]any{"count": i})
			time.Sleep(50 * time.Millisecond)
		}
		writer.Close()
	}()

	// Wait for at least one watcher call
	select {
	case <-watcherCalled:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for watcher to be called")
	}
}

func TestStreamingProvider_ReadError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, writer := io.Pipe()
	encoderReady := make(chan struct{})

	// Write initial config then signal ready
	go func() {
		encoder := gob.NewEncoder(writer)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value"})
		close(encoderReady)
	}()

	p, err := NewStreamingProvider(reader)
	require.NoError(t, err)

	watcherCalled := make(chan *confmap.ChangeEvent, 1)
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {
		watcherCalled <- event
	})
	require.NoError(t, err)
	defer ret.Close(ctx)

	// Wait for initial encode, then close the writer to cause a read error
	<-encoderReady
	writer.Close()

	// Wait for watcher to be called with error
	select {
	case event := <-watcherCalled:
		require.NotNil(t, event.Error)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for error event")
	}
}

func TestStreamingProvider_Shutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, writer := io.Pipe()

	// Write initial config
	go func() {
		encoder := gob.NewEncoder(writer)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value"})
		// Keep writer open so background reader is blocking
	}()

	p, err := NewStreamingProvider(reader)
	require.NoError(t, err)

	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	ret.Close(ctx)

	// Shutdown should succeed
	err = p.Shutdown(ctx)
	require.NoError(t, err)

	// Clean up
	writer.Close()
}

func TestStreamingProvider_RetrievedClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, writer := io.Pipe()

	// Write initial config
	go func() {
		encoder := gob.NewEncoder(writer)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value"})
	}()

	p, err := NewStreamingProvider(reader)
	require.NoError(t, err)

	watcherCalled := make(chan struct{})
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {
		close(watcherCalled)
	})
	require.NoError(t, err)

	// Close the retrieved - this should stop the watcher
	err = ret.Close(ctx)
	require.NoError(t, err)

	// Write another config - watcher should NOT be called since we closed
	go func() {
		encoder := gob.NewEncoder(writer)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value2"})
	}()

	// Give some time for the watcher to potentially be called
	select {
	case <-watcherCalled:
		t.Fatal("watcher was called after Close")
	case <-time.After(100 * time.Millisecond):
		// Success - watcher was not called
	}

	// Clean up
	writer.Close()
	p.Shutdown(ctx)
}

func TestStreamingProvider_WrongURI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	buf := encodeConfigToBuffer(map[string]any{"key": "value"})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)

	_, err = p.Retrieve(ctx, "wrong:uri", func(event *confmap.ChangeEvent) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uri doesn't equal defined")
}

func TestStreamingProvider_NilReader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, err := NewStreamingProvider(nil)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Retrieve should fail because no config is available
	_, err = p.Retrieve(ctx, p.URI(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no configuration available")
}

func TestStreamingProvider_EmptyConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	buf := encodeConfigToBuffer(map[string]any{})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)

	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	defer ret.Close(ctx)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Equal(t, 0, len(retCfg.AllKeys()))
}

func TestStreamingProvider_InvalidGobData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Write invalid gob data
	buf := bytes.NewReader([]byte("invalid gob data"))

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)

	// Error should occur on Retrieve, not NewStreamingProvider
	_, err = p.Retrieve(ctx, p.URI(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode config")
}

func TestStreamingProvider_IncompleteGobData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Write truncated gob data
	buf := bytes.NewReader([]byte{0x0c, 0xff, 0x81})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)

	// Error should occur on Retrieve, not NewStreamingProvider
	_, err = p.Retrieve(ctx, p.URI(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode config")
}

func TestStreamingProvider_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	buf := encodeConfigToBuffer(map[string]any{"key": "value"})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)

	// Retrieve should fail immediately with cancelled context
	_, err = p.Retrieve(ctx, p.URI(), nil)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestStreamingProvider_NilWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	buf := encodeConfigToBuffer(map[string]any{"key": "value"})

	p, err := NewStreamingProvider(buf)
	require.NoError(t, err)

	// Should work fine with nil watcher
	ret, err := p.Retrieve(ctx, p.URI(), nil)
	require.NoError(t, err)
	defer ret.Close(ctx)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "value", retCfg.Get("key"))
}
