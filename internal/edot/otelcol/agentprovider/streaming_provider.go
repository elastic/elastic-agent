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
// Each Retrieve call starts a watcher goroutine that signals config changes
// via the WatcherFunc. The watcher is stopped by calling Retrieved.Close.
//
// Per the confmap.Provider contract, Retrieve and Shutdown are never called
// concurrently with themselves or each other.
type StreamingProvider struct {
	// reader is the pipe/stdin reader (set by NewFactoryWithReader).
	reader io.ReadCloser

	// decoder is created on first Retrieve call
	decoder *gob.Decoder

	// cond is broadcast when config is updated or an error occurs.
	// Watcher goroutines wait on it using the generation counter to detect changes.
	// Also protects cfg, readErr, generation, and closed.
	cond       *sync.Cond
	cfg        *confmap.Conf
	readErr    error
	generation uint64
	closed     bool // set by Shutdown to make watchers exit without error

	// wg tracks all goroutines (background reader + watch loops) so
	// Shutdown can wait for them to finish.
	wg sync.WaitGroup

	// stopCh signals the background reader to stop
	backgroundReaderOnce sync.Once
	stopCh               chan struct{}
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
	p := &StreamingProvider{
		reader: reader,
		cond:   sync.NewCond(&sync.Mutex{}),
		stopCh: make(chan struct{}),
	}
	return confmap.NewProviderFactory(func(_ confmap.ProviderSettings) confmap.Provider {
		return p
	})
}

// readConfig reads a single config from the stream.
// The config is transmitted as gob-encoded YAML bytes.
// Returns the parsed config or an error.
func (p *StreamingProvider) readConfig() (*confmap.Conf, error) {
	if p.decoder == nil {
		return nil, errors.New("decoder not initialized")
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
// and broadcasts updates to all watchers via the condition variable.
// Called only once.
func (p *StreamingProvider) startBackgroundReader() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			select {
			case <-p.stopCh:
				return
			default:
			}

			cfg, err := p.readConfig()

			p.cond.L.Lock()
			if err != nil {
				p.readErr = err
			} else {
				p.cfg = cfg
			}
			p.generation++
			p.cond.Broadcast()
			p.cond.L.Unlock()

			if err != nil {
				return
			}
		}
	}()
}

// Retrieve returns the latest configuration and starts watching for updates.
// On the first call, it creates a gob decoder from the reader, reads the
// initial config synchronously, and starts a background reader. The returned
// Retrieved.Close must be called to stop the watcher goroutine.
//
// Per the confmap.Provider contract, this method is never called concurrently
// with itself or with Shutdown.
func (p *StreamingProvider) Retrieve(ctx context.Context, _ string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Check for any read errors from the background reader
	p.cond.L.Lock()
	if p.readErr != nil {
		err := p.readErr
		p.cond.L.Unlock()
		return nil, fmt.Errorf("config read error: %w", err)
	}
	p.cond.L.Unlock()

	// On first Retrieve call: set up the decoder and read initial config
	if p.decoder == nil {
		if p.reader == nil {
			return nil, errors.New("no reader configured")
		}
		p.decoder = gob.NewDecoder(p.reader)

		cfg, err := p.readConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to read initial config: %w", err)
		}
		p.cfg = cfg
		// Start background reader after first config is read
		p.backgroundReaderOnce.Do(p.startBackgroundReader)
	}

	// Get latest config at time of call
	p.cond.L.Lock()
	cfg := p.cfg
	p.cond.L.Unlock()

	if cfg == nil {
		return nil, errors.New("no configuration available")
	}

	// Start watcher goroutine if watcher callback provided.
	// Each watcher gets its own stopped flag, protected by the cond's mutex,
	// so Retrieved.Close can signal it to exit without affecting other watchers.
	// We capture the current generation here (synchronously) so the watcher
	// won't miss updates that occur before the goroutine is scheduled.
	stopped := false
	if watcher != nil {
		p.cond.L.Lock()
		startGen := p.generation
		p.cond.L.Unlock()
		p.wg.Add(1)
		go func() {
			p.watchLoop(ctx, watcher, &stopped, startGen)
			defer p.wg.Done()
		}()
	}

	// Return Retrieved with close function that stops the watcher
	return confmap.NewRetrieved(cfg.ToStringMap(), confmap.WithRetrievedClose(func(context.Context) error {
		p.cond.L.Lock()
		stopped = true
		p.cond.L.Unlock()
		p.cond.Broadcast()
		return nil
	}))
}

// watchLoop runs in a goroutine for each active watcher. It calls the watcher
// callback on every config update or error, looping until stopped (by
// Retrieved.Close setting *stopped=true) or until the caller's context is
// cancelled.
func (p *StreamingProvider) watchLoop(ctx context.Context, watcher confmap.WatcherFunc, stopped *bool, lastGen uint64) {
	for {
		// Wait for the next generation change or stop signal
		p.cond.L.Lock()
		for p.generation == lastGen && !*stopped && !p.closed {
			p.cond.Wait()
		}
		if *stopped || p.closed {
			p.cond.L.Unlock()
			return
		}
		lastGen = p.generation
		readErr := p.readErr
		p.cond.L.Unlock()

		// If the caller's context is cancelled, stop silently
		if ctx.Err() != nil {
			return
		}

		if readErr != nil {
			watcher(&confmap.ChangeEvent{Error: readErr})
			return
		}

		watcher(&confmap.ChangeEvent{})
	}
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
	close(p.stopCh)
	// Set the closed flag BEFORE closing the reader so any watchers that
	// wake up from the broadcast (caused by the reader close error) see
	// the flag and exit cleanly without calling the WatcherFunc. This
	// prevents a deadlock where the watcher tries to send on the
	// configProvider's Watch channel after the collector's run loop has
	// already exited.
	p.cond.L.Lock()
	p.closed = true
	p.cond.L.Unlock()
	p.cond.Broadcast()
	// Close the underlying reader to unblock any pending Decode.
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
