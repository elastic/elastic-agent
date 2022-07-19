// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package gateway

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

// FleetGateway is a gateway between the Agent and the Fleet API, it's take cares of all the
// bidirectional communication requirements. The gateway aggregates events and will periodically
// call the API to send the events and will receive actions to be executed locally.
// The only supported action for now is a "ActionPolicyChange".
type FleetGateway interface {
	// Run runs the gateway.
	Run(ctx context.Context) error

	// Errors returns the channel to watch for reported errors.
	Errors() <-chan error

	// SetClient sets the client for the gateway.
	SetClient(client.Sender)
}
