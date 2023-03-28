// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
)

// StateFetcher provides an interface to fetch the current state of the coordinator.
type StateFetcher interface {
	// StateSubscribe subscribes to changes in the coordinator state.
	//
	// This provides the current state at the time of first subscription. Cancelling the context
	// results in the subscription being unsubscribed.
	//
	// Note: Not reading from a subscription channel will cause the Coordinator to block.
	StateSubscribe(ctx context.Context) state.StateUpdateSource
}
