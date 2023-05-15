// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package composable

import (
	"context"
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// DynamicProviderComm is the interface that an dynamic provider uses to communicate back to Elastic Agent.
type DynamicProviderComm interface {
	context.Context

	// AddOrUpdate updates a mapping with given ID with latest mapping and processors.
	//
	// `priority` ensures that order is maintained when adding the mapping to the current state
	// for the processor. Lower priority mappings will always be sorted before higher priority mappings
	// to ensure that matching of variables occurs on the lower priority mappings first.
	AddOrUpdate(id string, priority int, mapping map[string]interface{}, processors []map[string]interface{}) error
	// Remove removes a mapping by given ID.
	Remove(id string)
}

// DynamicProvider is the interface that a dynamic provider must implement.
type DynamicProvider interface {
	// Run runs the inventory provider.
	Run(DynamicProviderComm) error
}

// DynamicProviderBuilder creates a new dynamic provider based on the given config and returns it.
type DynamicProviderBuilder func(log *logger.Logger, config *config.Config, managed bool) (DynamicProvider, error)

// MustAddDynamicProvider adds a new DynamicProviderBuilder and panics if it AddDynamicProvider returns an error.
func (r *providerRegistry) MustAddDynamicProvider(name string, builder DynamicProviderBuilder) {
	err := r.AddDynamicProvider(name, builder)
	if err != nil {
		panic(err)
	}
}

// AddDynamicProvider adds a new DynamicProviderBuilder
//
//nolint:dupl,goimports,nolintlint // false positive
func (r *providerRegistry) AddDynamicProvider(providerName string, builder DynamicProviderBuilder) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if providerName == "" {
		return fmt.Errorf("provider providerName is required")
	}
	if strings.ToLower(providerName) != providerName {
		return fmt.Errorf("provider providerName must be lowercase")
	}
	_, contextExists := r.contextProviders[providerName]
	_, dynamicExists := r.dynamicProviders[providerName]
	if contextExists || dynamicExists {
		return fmt.Errorf("provider '%s' is already registered", providerName)
	}
	if builder == nil {
		return fmt.Errorf("provider '%s' cannot be registered with a nil factory", providerName)
	}

	r.dynamicProviders[providerName] = builder
	r.logger.Debugf("Registered provider: %s", providerName)
	return nil
}

// GetDynamicProvider returns the dynamic provider with the giving name, nil if it doesn't exist
func (r *providerRegistry) GetDynamicProvider(name string) (DynamicProviderBuilder, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	b, ok := r.dynamicProviders[name]
	return b, ok
}
