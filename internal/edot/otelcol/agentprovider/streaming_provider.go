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
	"strings"
	"sync"

	"go.opentelemetry.io/collector/confmap"
)

// build time guard that StreamingProvider implements confmap.Provider
var _ confmap.Provider = (*StreamingProvider)(nil)

// StreamingProvider is a config provider that reads configs from a Unix domain
// socket (or Windows named pipe) using gob-encoded YAML bytes. On the first
// Retrieve call, it dials the socket address extracted from the URI, reads the
// initial config synchronously, and starts a background reader for subsequent
// configs. Each Retrieve call starts a watcher goroutine that signals config
// changes via the WatcherFunc. The watcher is stopped by calling Retrieved.Close.
//
// Per the confmap.Provider contract, Retrieve and Shutdown are never called
// concurrently with themselves or each other.
type StreamingProvider struct {
	// conn is the socket connection, established on first Retrieve call
	conn net.Conn

	// dialFunc dials the socket address. Defaults to the platform-specific
	// dialSocket function. Can be overridden for testing.
	dialFunc func(ctx context.Context, address string) (net.Conn, error)

	// decoder is created on first Retrieve call
	decoder *gob.Decoder

	// cfg holds the latest config, protected by cfgMu for access from background reader
	cfg   *confmap.Conf
	cfgMu sync.RWMutex

	// updated is signaled when a new config is available
	updated chan struct{}

	// readErr holds any error from the background reader, protected by readErrMu
	readErr   error
	readErrMu sync.RWMutex

	// stopCh signals the background reader to stop
	backgroundReaderStarted bool
	stopCh                  chan struct{}
}

// NewFactory returns a confmap.ProviderFactory that creates a StreamingProvider.
// The returned factory always creates the same shared provider instance.
func NewFactory() confmap.ProviderFactory {
	return NewFactoryWithDialFunc(dialSocket)
}

// NewFactoryWithDialFunc returns a confmap.ProviderFactory using the given dial
// function. This is useful for testing where a real socket is not desired.
func NewFactoryWithDialFunc(dialFunc func(ctx context.Context, address string) (net.Conn, error)) confmap.ProviderFactory {
	p := &StreamingProvider{
		dialFunc: dialFunc,
		updated:  make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
	}
	return confmap.NewProviderFactory(func(_ confmap.ProviderSettings) confmap.Provider {
		return p
	})
}

// readConfig reads a single config from the stream.
// The config is transmitted as gob-encoded YAML bytes.
// Returns the parsed config or an error.
// The context can be used to cancel a blocking read.
func (p *StreamingProvider) readConfig(ctx context.Context) (*confmap.Conf, error) {
	if p.decoder == nil {
		return nil, errors.New("decoder not initialized")
	}

	// Check context before blocking on decode
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Decode blocks until data is available or the connection is closed.
	// Context cancellation requires closing the underlying connection.
	var yamlBytes []byte
	if err := p.decoder.Decode(&yamlBytes); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	retrieved, err := confmap.NewRetrievedFromYAML(yamlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	conf, err := retrieved.AsConf()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config to confmap: %w", err)
	}

	return conf, nil
}

// startBackgroundReader starts a goroutine that reads subsequent configs
// and signals updates via the updated channel. Called only once.
func (p *StreamingProvider) startBackgroundReader() {
	if p.backgroundReaderStarted {
		return
	}
	p.backgroundReaderStarted = true

	go func() {
		for {
			select {
			case <-p.stopCh:
				return
			default:
			}

			cfg, err := p.readConfig(context.Background())
			if err != nil {
				p.readErrMu.Lock()
				p.readErr = err
				p.readErrMu.Unlock()
				// Signal error so watchers can wake up and check
				select {
				case p.updated <- struct{}{}:
				default:
				}
				return
			}

			p.cfgMu.Lock()
			p.cfg = cfg
			p.cfgMu.Unlock()

			// Signal that config was updated
			select {
			case p.updated <- struct{}{}:
			default:
				// already has an updated state pending
			}
		}
	}()
}

// Retrieve returns the latest configuration and starts watching for updates.
// On the first call, it extracts the socket address from the URI (by stripping
// the "elasticagent:" prefix), dials the socket, reads the initial config
// synchronously, and starts a background reader. The returned Retrieved.Close
// must be called to stop the watcher goroutine.
//
// Per the confmap.Provider contract, this method is never called concurrently
// with itself or with Shutdown.
func (p *StreamingProvider) Retrieve(ctx context.Context, uri string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Check for any read errors from the background reader
	p.readErrMu.RLock()
	if p.readErr != nil {
		err := p.readErr
		p.readErrMu.RUnlock()
		return nil, fmt.Errorf("config read error: %w", err)
	}
	p.readErrMu.RUnlock()

	// On first Retrieve call: dial the socket and read initial config
	if p.decoder == nil {
		address := strings.TrimPrefix(uri, AgentConfigProviderSchemeName+":")
		conn, err := p.dialFunc(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("failed to dial config socket %q: %w", address, err)
		}
		p.conn = conn
		p.decoder = gob.NewDecoder(conn)

		cfg, err := p.readConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read initial config: %w", err)
		}
		p.cfg = cfg
		// Start background reader after first config is read
		p.startBackgroundReader()
	}

	// Get latest config at time of call
	p.cfgMu.RLock()
	cfg := p.cfg
	p.cfgMu.RUnlock()

	if cfg == nil {
		return nil, errors.New("no configuration available")
	}

	// Create stop channel for this watcher
	watcherStopCh := make(chan struct{})

	// Start watcher goroutine if watcher callback provided
	if watcher != nil {
		go func() {
			select {
			case <-watcherStopCh:
				return
			case <-p.updated:
				// Check for read errors before calling watcher
				p.readErrMu.RLock()
				readErr := p.readErr
				p.readErrMu.RUnlock()
				if readErr != nil {
					watcher(&confmap.ChangeEvent{Error: readErr})
					return
				}

				// If the caller's context is cancelled, don't call watcher
				if ctx.Err() != nil {
					return
				}
				watcher(&confmap.ChangeEvent{})
			}
		}()
	}

	// Return Retrieved with close function that stops the watcher
	return confmap.NewRetrieved(cfg.ToStringMap(), confmap.WithRetrievedClose(func(context.Context) error {
		close(watcherStopCh)
		return nil
	}))
}

// Scheme is the scheme for this provider.
func (p *StreamingProvider) Scheme() string {
	return AgentConfigProviderSchemeName
}

// Shutdown called by collector when stopping. Stops the background reader
// and closes the socket connection.
//
// Per the confmap.Provider contract, this method is never called concurrently
// with itself or with Retrieve.
func (p *StreamingProvider) Shutdown(_ context.Context) error {
	if p.backgroundReaderStarted {
		close(p.stopCh)
	}
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}
