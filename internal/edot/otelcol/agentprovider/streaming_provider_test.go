// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v2"
)

// testURI returns a URI for the given socket address that matches what the
// parent process would pass via --config.
func testURI(addr string) string {
	return fmt.Sprintf("%s:%s", AgentConfigProviderSchemeName, addr)
}

// encodeYAMLBytes marshals config to YAML and encodes the bytes using gob.
func encodeYAMLBytes(encoder *gob.Encoder, cfg map[string]any) error {
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return encoder.Encode(yamlBytes)
}

// newTestProvider creates a StreamingProvider backed by a net.Pipe().
// It returns the provider, the server-side connection (for writing configs),
// and the URI to use with Retrieve.
func newTestProvider(t *testing.T) (confmap.Provider, net.Conn, string) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	const fakeAddr = "unix:///tmp/test.sock"

	factory := NewFactoryWithDialFunc(func(_ context.Context, address string) (net.Conn, error) {
		assert.Equal(t, fakeAddr, address)
		return clientConn, nil
	})
	provider := factory.Create(confmap.ProviderSettings{})
	return provider, serverConn, testURI(fakeAddr)
}

func TestStreamingProvider_NewFactory(t *testing.T) {
	clientConn, _ := net.Pipe()

	factory := NewFactoryWithDialFunc(func(_ context.Context, _ string) (net.Conn, error) {
		return clientConn, nil
	})
	p1 := factory.Create(confmap.ProviderSettings{})
	p2 := factory.Create(confmap.ProviderSettings{})
	// Factory always returns the same provider instance
	assert.Same(t, p1, p2)
}

func TestStreamingProvider_Scheme(t *testing.T) {
	p, serverConn, _ := newTestProvider(t)
	defer serverConn.Close()
	assert.Equal(t, AgentConfigProviderSchemeName, p.Scheme())
}

func TestStreamingProvider_InitialConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, serverConn, uri := newTestProvider(t)

	cfg := map[string]any{"receivers": map[string]any{"otlp": map[string]any{}}}

	// Write initial config before Retrieve
	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, cfg)
	}()

	ret, err := p.Retrieve(ctx, uri, func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	defer ret.Close(ctx)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)

	// Verify the config was read correctly
	assert.NotNil(t, retCfg.Get("receivers"))

	serverConn.Close()
	p.Shutdown(ctx)
}

func TestStreamingProvider_ConfigUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, serverConn, uri := newTestProvider(t)

	initialCfg := map[string]any{"version": "1"}
	updatedCfg := map[string]any{"version": "2"}

	readyCh := make(chan *gob.Encoder)
	configWritten := make(chan struct{})

	// Write initial config
	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, initialCfg)
		readyCh <- encoder
	}()

	watcherCalled := make(chan struct{})
	ret, err := p.Retrieve(ctx, uri, func(event *confmap.ChangeEvent) {
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
	ret2, err := p.Retrieve(ctx, uri, nil)
	require.NoError(t, err)
	defer ret2.Close(ctx)

	retCfg2, err := ret2.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "2", retCfg2.Get("version"))

	// Clean up
	serverConn.Close()
	p.Shutdown(ctx)
}

func TestStreamingProvider_MultipleUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, serverConn, uri := newTestProvider(t)

	readyCh := make(chan *gob.Encoder)

	// Write initial config
	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, map[string]any{"count": 0})
		readyCh <- encoder
	}()

	// Track watcher calls
	var watcherCallCount int
	var watcherMu sync.Mutex
	watcherCalled := make(chan struct{}, 10)

	ret, err := p.Retrieve(ctx, uri, func(event *confmap.ChangeEvent) {
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
		serverConn.Close()
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

	p, serverConn, uri := newTestProvider(t)

	encoderReady := make(chan struct{})

	// Write initial config then signal ready
	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value"})
		close(encoderReady)
	}()

	watcherCalled := make(chan *confmap.ChangeEvent, 1)
	ret, err := p.Retrieve(ctx, uri, func(event *confmap.ChangeEvent) {
		watcherCalled <- event
	})
	require.NoError(t, err)
	defer ret.Close(ctx)

	// Wait for initial encode, then close the connection to cause a read error
	<-encoderReady
	serverConn.Close()

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

	p, serverConn, uri := newTestProvider(t)

	// Write initial config
	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value"})
		// Keep connection open so background reader is blocking
	}()

	ret, err := p.Retrieve(ctx, uri, func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	ret.Close(ctx)

	// Shutdown should succeed and close the connection
	err = p.Shutdown(ctx)
	require.NoError(t, err)

	// Clean up
	serverConn.Close()
}

func TestStreamingProvider_RetrievedClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, serverConn, uri := newTestProvider(t)

	readyCh := make(chan *gob.Encoder)

	// Write initial config
	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value"})
		readyCh <- encoder
	}()

	watcherCalled := make(chan struct{})
	ret, err := p.Retrieve(ctx, uri, func(event *confmap.ChangeEvent) {
		close(watcherCalled)
	})
	require.NoError(t, err)

	// Close the retrieved - this should stop the watcher
	err = ret.Close(ctx)
	require.NoError(t, err)

	// Write another config - watcher should NOT be called since we closed
	encoder := <-readyCh
	go func() {
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
	serverConn.Close()
	p.Shutdown(ctx)
}

func TestStreamingProvider_DialError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialErr := errors.New("connection refused")
	factory := NewFactoryWithDialFunc(func(_ context.Context, _ string) (net.Conn, error) {
		return nil, dialErr
	})
	p := factory.Create(confmap.ProviderSettings{})

	_, err := p.Retrieve(ctx, testURI("unix:///nonexistent.sock"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to dial config socket")
}

func TestStreamingProvider_EmptyConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, serverConn, uri := newTestProvider(t)

	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, map[string]any{})
	}()

	ret, err := p.Retrieve(ctx, uri, func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	defer ret.Close(ctx)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Equal(t, 0, len(retCfg.AllKeys()))

	serverConn.Close()
	p.Shutdown(ctx)
}

func TestStreamingProvider_InvalidGobData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, serverConn, uri := newTestProvider(t)

	// Write invalid gob data directly to the connection
	go func() {
		_, _ = serverConn.Write([]byte("invalid gob data"))
		serverConn.Close()
	}()

	// Error should occur on Retrieve during initial config read
	_, err := p.Retrieve(ctx, uri, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode config")
}

func TestStreamingProvider_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	factory := NewFactoryWithDialFunc(func(_ context.Context, _ string) (net.Conn, error) {
		return clientConn, nil
	})
	p := factory.Create(confmap.ProviderSettings{})

	// Retrieve should fail immediately with cancelled context
	_, err := p.Retrieve(ctx, testURI("unix:///tmp/test.sock"), nil)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestStreamingProvider_NilWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, serverConn, uri := newTestProvider(t)

	go func() {
		encoder := gob.NewEncoder(serverConn)
		_ = encodeYAMLBytes(encoder, map[string]any{"key": "value"})
	}()

	// Should work fine with nil watcher
	ret, err := p.Retrieve(ctx, uri, nil)
	require.NoError(t, err)
	defer ret.Close(ctx)

	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	assert.Equal(t, "value", retCfg.Get("key"))

	serverConn.Close()
	p.Shutdown(ctx)
}
