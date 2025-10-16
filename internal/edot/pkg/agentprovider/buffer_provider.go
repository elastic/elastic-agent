// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"context"
	"fmt"
	"io"

	"github.com/gofrs/uuid/v5"
	"go.opentelemetry.io/collector/confmap"
)

// build time guard that BufferProvider implements confmap.Provider
var _ confmap.Provider = (*BufferProvider)(nil)

// BufferProvider is a fixed provider that has a factory but only returns the same provider.
type BufferProvider struct {
	uri string
	cfg *confmap.Conf
}

// NewBufferProvider creates a `agentprovider.BufferProvider`.
func NewBufferProvider(in io.Reader) (*BufferProvider, error) {
	uri := fmt.Sprintf("%s:%s", AgentConfigProviderSchemeName, uuid.Must(uuid.NewV4()).String())

	if in == nil {
		return &BufferProvider{
			uri: uri,
			cfg: nil,
		}, nil
	}

	configBytes, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read config from buffer: %w", err)
	}

	retrieved, err := confmap.NewRetrievedFromYAML(configBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config from buffer: %w", err)
	}

	conf, err := retrieved.AsConf()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config to confmap: %w", err)
	}

	return &BufferProvider{
		uri: uri,
		cfg: conf,
	}, nil
}

// NewFactory provides a factory. This factory doesn't create a new provider on each call. It always returns the same provider.
func (p *BufferProvider) NewFactory() confmap.ProviderFactory {
	return confmap.NewProviderFactory(func(_ confmap.ProviderSettings) confmap.Provider {
		return p
	})
}

// Retrieve returns the latest configuration.
func (p *BufferProvider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if uri != p.uri {
		return nil, fmt.Errorf("%q uri doesn't equal defined %q provider", uri, AgentConfigProviderSchemeName)
	}
	return confmap.NewRetrieved(p.cfg.ToStringMap())
}

// Scheme is the scheme for this provider.
func (p *BufferProvider) Scheme() string {
	return AgentConfigProviderSchemeName
}

// Shutdown called by collect when stopping.
func (p *BufferProvider) Shutdown(context.Context) error {
	return nil
}

// URI returns the URI to be used for this provider.
func (p *BufferProvider) URI() string {
	return p.uri
}
