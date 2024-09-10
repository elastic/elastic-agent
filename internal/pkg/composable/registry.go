// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composable

import (
	"sync"

	"github.com/elastic/elastic-agent-libs/logp"
)

// providerRegistry is a registry of providers
type providerRegistry struct {
	contextProviders map[string]ContextProviderBuilder
	dynamicProviders map[string]DynamicProviderBuilder

	logger *logp.Logger
	lock   sync.RWMutex
}

// Providers holds all known providers, they must be added to it to enable them for use
var Providers = &providerRegistry{
	contextProviders: make(map[string]ContextProviderBuilder),
	dynamicProviders: make(map[string]DynamicProviderBuilder),
	logger:           logp.NewLogger("dynamic"),
}
