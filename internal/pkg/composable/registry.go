// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composable

import (
	"sync"

	"github.com/elastic/elastic-agent-libs/logp"
)

// ProviderRegistry is a registry of providers
type ProviderRegistry struct {
	contextProviders map[string]ContextProviderBuilder
	dynamicProviders map[string]DynamicProviderBuilder

	logger *logp.Logger
	lock   sync.RWMutex
}

// NewProviderRegistry creates a new provider registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		contextProviders: make(map[string]ContextProviderBuilder),
		dynamicProviders: make(map[string]DynamicProviderBuilder),
		logger:           logp.NewLogger("composable"),
	}
}

// Providers holds all known providers, they must be added to it to enable them for use
var Providers = NewProviderRegistry()
