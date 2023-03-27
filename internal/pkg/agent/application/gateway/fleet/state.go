// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import "github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"

// StateFetcher provides an interface to fetch the current state of the coordinator.
type StateFetcher interface {
	// State returns the current state of the coordinator.
	State() state.State
}
