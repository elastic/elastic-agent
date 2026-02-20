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

	// mu protects yamlCfg and readErr.
	mu      sync.Mutex
	yamlCfg []byte
	readErr error

	// notifier broadcasts config updates to all active watchers.
	notifier *Notifier

	// wg tracks all goroutines (background reader + watch loops) so
	// Shutdown can wait for them to finish.
	wg sync.WaitGroup

	// stopCh signals the background reader and watchers to stop
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
		reader:   reader,
		notifier: NewNotifier(),
		stopCh:   make(chan struct{}),
	}
	return confmap.NewProviderFactory(func(_ confmap.ProviderSettings) confmap.Provider {
		return p
	})
}

// readFromPipe reads gob-encoded YAML bytes from the stream.
// Blocks until data is available or the connection is closed.
func (p *StreamingProvider) readFromPipe() ([]byte, error) {
	var yamlBytes []byte
	if err := p.decoder.Decode(&yamlBytes); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	return yamlBytes, nil
}

// startBackgroundReader starts a goroutine that reads subsequent configs
// and broadcasts updates to all watchers via the notifier.
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

			yamlBytes, err := p.readFromPipe()

			p.mu.Lock()
			if err != nil {
				p.readErr = err
			} else {
				p.yamlCfg = yamlBytes
			}
			p.mu.Unlock()

			p.notifier.Broadcast()

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
	p.mu.Lock()
	if p.readErr != nil {
		err := p.readErr
		p.mu.Unlock()
		return nil, fmt.Errorf("config read error: %w", err)
	}
	p.mu.Unlock()

	// On first Retrieve call: set up the decoder and read initial config
	if p.decoder == nil {
		p.decoder = gob.NewDecoder(p.reader)

		yamlBytes, err := p.readFromPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to read initial config: %w", err)
		}
		p.yamlCfg = yamlBytes
		// Start background reader after first config is read
		p.backgroundReaderOnce.Do(p.startBackgroundReader)
	}

	// Get latest config at time of call
	p.mu.Lock()
	yamlCfg := p.yamlCfg
	p.mu.Unlock()

	if yamlCfg == nil {
		return nil, errors.New("no configuration available")
	}

	// Start watcher goroutine if watcher callback provided.
	// Each watcher gets its own done channel so Retrieved.Close can signal
	// it to exit, and an exited channel so Close can wait for it to finish.
	var opts []confmap.RetrievedOption
	if watcher != nil {
		done := make(chan struct{})
		exited := make(chan struct{})
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer close(exited)
			for {
				waitCh := p.notifier.Wait()
				select {
				case <-waitCh:
					// During shutdown, stopCh is closed BEFORE the reader,
					// so any broadcast caused by the reader closing will
					// see stopCh already closed. Check it to avoid calling
					// the watcher after the collector's run loop has exited.
					select {
					case <-p.stopCh:
						return
					default:
					}

					p.mu.Lock()
					readErr := p.readErr
					p.mu.Unlock()

					if readErr != nil {
						watcher(&confmap.ChangeEvent{Error: readErr})
						return
					}
					watcher(&confmap.ChangeEvent{})
				case <-done:
					return
				case <-p.stopCh:
					return
				}
			}
		}()
		opts = append(opts, confmap.WithRetrievedClose(func(ctx context.Context) error {
			close(done)
			select {
			case <-exited:
			case <-ctx.Done():
			}
			return ctx.Err()
		}))
	}

	// Return Retrieved with close function that stops the watcher and
	// waits for the goroutine to exit, per the confmap.Provider contract.
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
	// Close stopCh BEFORE the reader so any watchers that wake up from a
	// broadcast (caused by the reader close error) see stopCh closed and
	// exit without calling the WatcherFunc. This prevents a deadlock where
	// the watcher tries to send on the configProvider's Watch channel after
	// the collector's run loop has already exited.
	close(p.stopCh)
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
