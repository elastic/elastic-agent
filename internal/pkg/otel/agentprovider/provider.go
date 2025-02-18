// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"context"
	"fmt"
	"sync"

	"github.com/gofrs/uuid/v5"
	"go.opentelemetry.io/collector/confmap"
)

const schemeName = "elasticagent"

// Provider is a fixed provider that has a factory but only returns the same provider.
type Provider struct {
	uri string

	cfg     *confmap.Conf
	cfgMu   sync.RWMutex
	updated chan struct{}

	canceller   context.CancelFunc
	cancelledMu sync.Mutex
}

// NewProvider creates a `agentprovider.Provider`.
func NewProvider(cfg *confmap.Conf) *Provider {
	uri := fmt.Sprintf("%s:%s", schemeName, uuid.Must(uuid.NewV4()).String())
	return &Provider{
		uri:     uri,
		cfg:     cfg,
		updated: make(chan struct{}, 1), // buffer of 1, stores the updated state
	}
}

// NewFactory provides a factory.
//
// This factory doesn't create a new provider on each call. It always returns the same provider.
func (p *Provider) NewFactory() confmap.ProviderFactory {
	return confmap.NewProviderFactory(func(_ confmap.ProviderSettings) confmap.Provider {
		return p
	})
}

// Update updates the latest configuration in the provider.
func (p *Provider) Update(cfg *confmap.Conf) {
	p.cfgMu.Lock()
	p.cfg = cfg
	p.cfgMu.Unlock()
	select {
	case p.updated <- struct{}{}:
	default:
		// already has an updated state
	}
}

// Retrieve returns the latest configuration.
func (p *Provider) Retrieve(ctx context.Context, uri string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if uri != p.uri {
		return nil, fmt.Errorf("%q uri doesn't equal defined %q provider", uri, schemeName)
	}

	// get latest cfg at time of call
	p.cfgMu.RLock()
	cfg := p.cfg
	p.cfgMu.RUnlock()

	// don't use passed in context, as the cancel comes from Shutdown
	ctx, cancel := context.WithCancel(context.Background())
	p.replaceCanceller(cancel)
	go func() {
		defer p.replaceCanceller(nil) // ensure the context is always cleaned up
		select {
		case <-ctx.Done():
			return
		case <-p.updated:
			watcher(&confmap.ChangeEvent{})
		}
	}()

	return confmap.NewRetrieved(cfg.ToStringMap())
}

// Scheme is the scheme for this provider.
func (p *Provider) Scheme() string {
	return schemeName
}

// Shutdown called by collect when stopping.
func (p *Provider) Shutdown(ctx context.Context) error {
	p.replaceCanceller(nil)
	return nil
}

// URI returns the URI to be used for this provider.
func (p *Provider) URI() string {
	return p.uri
}

func (p *Provider) replaceCanceller(replace context.CancelFunc) {
	p.cancelledMu.Lock()
	canceller := p.canceller
	p.canceller = replace
	p.cancelledMu.Unlock()
	if canceller != nil {
		canceller()
	}
}
