// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package composable

import (
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ContextProviderBuilder creates a new context provider based on the given config and returns it.
type ContextProviderBuilder func(log *logger.Logger, config *config.Config, managed bool) (corecomp.ContextProvider, error)

// MustAddContextProvider adds a new ContextProviderBuilder and panics if it AddContextProvider returns an error.
func (r *providerRegistry) MustAddContextProvider(name string, builder ContextProviderBuilder) {
	err := r.AddContextProvider(name, builder)
	if err != nil {
		panic(err)
	}
}

// AddContextProvider adds a new ContextProviderBuilder
//
//nolint:dupl,goimports,nolintlint // false positive
func (r *providerRegistry) AddContextProvider(name string, builder ContextProviderBuilder) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if name == "" {
		return fmt.Errorf("provider name is required")
	}

	if strings.ToLower(name) != name {
		return fmt.Errorf("provider name must be lowercase")
	}

	_, contextExists := r.contextProviders[name]
	_, dynamicExists := r.dynamicProviders[name]

	if contextExists || dynamicExists {
		return fmt.Errorf("provider '%s' is already registered", name)
	}
	if builder == nil {
		return fmt.Errorf("provider '%s' cannot be registered with a nil factory", name)
	}

	r.contextProviders[name] = builder
	r.logger.Debugf("Registered provider: %s", name)
	return nil
}

// GetContextProvider returns the context provider with the giving name, nil if it doesn't exist
func (r *providerRegistry) GetContextProvider(name string) (ContextProviderBuilder, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	b, ok := r.contextProviders[name]
	return b, ok
}
