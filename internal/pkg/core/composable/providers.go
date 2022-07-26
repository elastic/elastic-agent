// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package composable

import "context"

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

	// Set sets the current mapping for this context.
	Set(map[string]interface{}) error
}

// ContextProvider is the interface that a context provider must implement.
type ContextProvider interface {
	// Run runs the context provider.
	Run(ContextProviderComm) error
}
