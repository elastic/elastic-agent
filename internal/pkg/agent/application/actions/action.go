// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package actions

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

// Handler handles action coming from fleet.
type Handler interface {
	Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error
}

// ClientSetter sets the client for communication.
type ClientSetter interface {
	SetClient(client.Sender)
}
