// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"
)

// build time guard that StdinGobProvider implements confmap.Provider
var _ confmap.Provider = (*StdinGobProvider)(nil)

// StdinGobProvider is a config provider that reads gob-encoded YAML configs
// from an io.ReadCloser (typically the subprocess's stdin pipe). On the first
// Retrieve call, it creates a gob decoder from the reader, reads the initial
// config synchronously, and starts a background reader for subsequent configs.
// Watchers registered via Retrieve are kept in a map and called directly by the
// background reader whenever a new config (or error) arrives. Calling
// Retrieved.Close removes the watcher from the map.
//
// Per the confmap.Provider contract, Retrieve and Shutdown are never called
// concurrently with themselves or each other.
type StdinGobProvider struct {
	// reader is the pipe/stdin reader (set by NewStdinGobFactoryWithReader).
	reader io.ReadCloser

	// decoder is created on first Retrieve call
	decoder *gob.Decoder

	logger *zap.Logger

	// mu protects yamlCfg, readErr, and watchers.
	mu       sync.Mutex
	yamlCfg  []byte
	readErr  error
	watchers map[int]confmap.WatcherFunc
	nextID   int

	// wg tracks the background reader goroutine so Shutdown can wait
	// for it to finish.
	wg                     sync.WaitGroup
	backgroundReaderOnce   sync.Once
	backgroundReaderCtx    context.Context
	backgroundReaderCancel context.CancelFunc
}

// NewFactory returns a confmap.ProviderFactory that creates a
// StdinGobProvider reading from os.Stdin.
func NewFactory() confmap.ProviderFactory {
	return NewStdinGobFactoryWithReader(os.Stdin)
}

// NewStdinGobFactoryWithReader returns a confmap.ProviderFactory using the
// given reader (typically stdin). The provider reads gob-encoded configs
// directly from the reader.
func NewStdinGobFactoryWithReader(reader io.ReadCloser) confmap.ProviderFactory {
	return confmap.NewProviderFactory(
		func(settings confmap.ProviderSettings) confmap.Provider {
			return newProvider(reader, settings)
		},
	)
}

func newProvider(reader io.ReadCloser, settings confmap.ProviderSettings) confmap.Provider {
	backgroundReaderCtx, cancel := context.WithCancel(context.Background())
	return &StdinGobProvider{
		reader:                 reader,
		logger:                 settings.Logger,
		watchers:               make(map[int]confmap.WatcherFunc),
		backgroundReaderCtx:    backgroundReaderCtx,
		backgroundReaderCancel: cancel,
	}
}

// readCfgBytes reads gob-encoded YAML bytes from the stream.
// The call blocks until data is available, the connection is closed, or the
// context is cancelled.
func (p *StdinGobProvider) readCfgBytes(ctx context.Context) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result)
	go func() {
		var yamlBytes []byte
		err := p.decoder.Decode(&yamlBytes)
		ch <- result{yamlBytes, err}
		close(ch)
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("failed to decode config: %w", r.err)
		}
		return r.data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startBackgroundReader starts goroutines that read subsequent configs
// and call all registered watchers directly. Called only once.
func (p *StdinGobProvider) startBackgroundReader() {
	p.wg.Add(1)

	// The background reader goroutine exits after its context is cancelled.
	go func() {
		defer p.wg.Done()
		for {
			yamlCfg, readErr := p.readCfgBytes(p.backgroundReaderCtx)

			// EOF means the writer has no more configs to send. This is not an error — just stop reading and keep
			// serving the last known config.
			// Canceled means that we should exit because the provider is shutting down.
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, context.Canceled) {
				return
			}

			p.mu.Lock()
			if readErr != nil {
				p.readErr = readErr
			} else {
				p.yamlCfg = yamlCfg
			}

			// Call all watchers.
			for _, w := range p.watchers {
				go w(&confmap.ChangeEvent{Error: p.readErr})
			}
			p.mu.Unlock()
		}
	}()
}

// Retrieve returns the latest configuration and registers a watcher for updates.
// On the first call, it creates a gob decoder from the reader, reads the
// initial config synchronously, and starts a background reader. The returned
// Retrieved.Close must be called to unregister the watcher.
//
// Per the confmap.Provider contract, this method is never called concurrently
// with itself or with Shutdown.
func (p *StdinGobProvider) Retrieve(ctx context.Context, _ string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.readErr != nil {
		return nil, fmt.Errorf("config read error: %w", p.readErr)
	}

	// On first Retrieve call: set up the decoder and read initial config
	if p.decoder == nil {
		p.decoder = gob.NewDecoder(p.reader)

		yamlBytes, err := p.readCfgBytes(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read initial config: %w", err)
		}
		p.yamlCfg = yamlBytes
		// Start background reader after first config is read
		p.backgroundReaderOnce.Do(p.startBackgroundReader)
	}

	// Get latest config at time of call
	yamlCfg := p.yamlCfg

	if yamlCfg == nil {
		return nil, errors.New("no configuration available")
	}

	// Register watcher if provided. Retrieved.Close removes it from the map.
	var opts []confmap.RetrievedOption
	if watcher != nil {
		id := p.nextID
		p.nextID++
		p.watchers[id] = watcher

		opts = append(opts, confmap.WithRetrievedClose(func(ctx context.Context) error {
			p.mu.Lock()
			defer p.mu.Unlock()
			delete(p.watchers, id)
			return nil
		}))
	}

	return confmap.NewRetrievedFromYAML(yamlCfg, opts...)
}

// Scheme is the scheme for this provider.
func (p *StdinGobProvider) Scheme() string {
	return StdinGobProviderSchemeName
}

// Shutdown is called by the collector when stopping. It signals the background
// reader to stop and waits for it to finish.
//
// Per the confmap.Provider contract, this method is never called concurrently
// with itself or with Retrieve.
func (p *StdinGobProvider) Shutdown(ctx context.Context) error {
	p.backgroundReaderCancel()
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}
