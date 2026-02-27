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
)

// build time guard that StreamingProvider implements confmap.Provider
var _ confmap.Provider = (*StreamingProvider)(nil)

// StreamingProvider is a config provider that reads gob-encoded YAML configs
// from an io.ReadCloser (typically the subprocess's stdin pipe). On the first
// Retrieve call, it creates a gob decoder from the reader, reads the initial
// config synchronously, and starts a background reader for subsequent configs.
// Watchers registered via Retrieve are kept in a map and called directly by the
// background reader whenever a new config (or error) arrives. Calling
// Retrieved.Close removes the watcher from the map.
//
// Per the confmap.Provider contract, Retrieve and Shutdown are never called
// concurrently with themselves or each other.
type StreamingProvider struct {
	// reader is the pipe/stdin reader (set by NewFactoryWithReader).
	reader io.ReadCloser

	// decoder is created on first Retrieve call
	decoder *gob.Decoder

	// mu protects yamlCfg, readErr, and watchers.
	mu       sync.Mutex
	yamlCfg  []byte
	readErr  error
	watchers map[int]confmap.WatcherFunc
	nextID   int

	// wg tracks the background reader goroutine so Shutdown can wait
	// for it to finish.
	wg sync.WaitGroup

	backgroundReaderOnce sync.Once
	ctx                  context.Context
	cancel               context.CancelFunc
}

// NewFactory returns a confmap.ProviderFactory that creates a StreamingProvider
// reading from stdin. An io.Pipe is used as an intermediary so that closing the
// reader in Shutdown reliably unblocks any pending gob.Decode — unlike
// os.Stdin.Close(), io.PipeReader.Close() always wakes blocked readers.
func NewFactory() confmap.ProviderFactory {
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.Copy(pw, os.Stdin)
		pw.Close()
	}()
	return NewFactoryWithReader(pr)
}

// NewFactoryWithReader returns a confmap.ProviderFactory using the given reader
// (typically stdin). The provider reads gob-encoded configs directly from the
// reader without dialing any socket.
func NewFactoryWithReader(reader io.ReadCloser) confmap.ProviderFactory {
	ctx, cancel := context.WithCancel(context.Background())
	p := &StreamingProvider{
		reader:   reader,
		watchers: make(map[int]confmap.WatcherFunc),
		ctx:      ctx,
		cancel:   cancel,
	}
	return confmap.NewProviderFactory(func(_ confmap.ProviderSettings) confmap.Provider {
		return p
	})
}

// readFromPipe reads gob-encoded YAML bytes from the stream.
// The call blocks until data is available, the connection is closed, or the
// context is cancelled.
func (p *StreamingProvider) readFromPipe(ctx context.Context) ([]byte, error) {
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

// startBackgroundReader starts a goroutine that reads subsequent configs
// and calls all registered watchers directly. Called only once.
func (p *StreamingProvider) startBackgroundReader() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			yamlCfg, readErr := p.readFromPipe(p.ctx)

			p.mu.Lock()
			if readErr != nil {
				p.readErr = readErr
			} else {
				p.yamlCfg = yamlCfg
			}

			// During shutdown, ctx is cancelled BEFORE the reader is closed.
			// Check it to avoid calling watchers after the collector's run
			// loop has already exited.
			if p.ctx.Err() != nil {
				p.mu.Unlock()
				return
			}

			// Call all watchers.
			for _, w := range p.watchers {
				go w(&confmap.ChangeEvent{Error: p.readErr})
			}
			p.mu.Unlock()

			if readErr != nil {
				return
			}
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
func (p *StreamingProvider) Retrieve(ctx context.Context, _ string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.readErr != nil {
		return nil, fmt.Errorf("config read error: %w", p.readErr)
	}

	// On first Retrieve call: set up the decoder and read initial config
	if p.decoder == nil {
		p.decoder = gob.NewDecoder(p.reader)

		yamlBytes, err := p.readFromPipe(ctx)
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
func (p *StreamingProvider) Scheme() string {
	return AgentConfigProviderSchemeName
}

// Shutdown called by collector when stopping. Stops the background reader
// and closes the reader.
//
// Per the confmap.Provider contract, this method is never called concurrently
// with itself or with Retrieve.
func (p *StreamingProvider) Shutdown(ctx context.Context) error {
	// Cancel the provider context BEFORE closing the reader so the background
	// reader sees cancellation and skips calling watchers when it wakes from
	// the read error caused by closing the reader.
	p.cancel()
	// Close the underlying reader to unblock any pending Decode goroutine.
	if p.reader != nil {
		_ = p.reader.Close()
	}
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
