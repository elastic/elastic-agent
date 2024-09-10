// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composable

import (
	"context"
)

// FetchContextProvider is the interface that a context provider uses allow variable values to be determined when the
// configuration is rendered versus it being known in advanced.
type FetchContextProvider interface {
	ContextProvider

	// Fetch tries to fetch a value for a variable.
	Fetch(string) (string, bool)
}

// ContextProviderComm is the interface that a context provider uses to communicate back to Elastic Agent.
type ContextProviderComm interface {
	context.Context

	// Signal signals that something has changed in the provider.
	//
	// Note: This should only be used by fetch context providers, standard context
	// providers should use Set to update the overall state.
	Signal()

	// Set sets the current mapping for this context.
	Set(map[string]interface{}) error
}

// ContextProvider is the interface that a context provider must implement.
type ContextProvider interface {
	// Run runs the context provider.
	Run(context.Context, ContextProviderComm) error
}

// CloseableProvider is an interface that providers may choose to implement
// if it makes sense for them, e.g. if they have any resources that need
// cleaning up after the provider's (final) run.
type CloseableProvider interface {
	// Close is called after all runs of the provider have finished.
	Close() error
}
