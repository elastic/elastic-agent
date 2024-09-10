// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package acker

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

// Acker is an acker of actions to fleet.
type Acker interface {
	Ack(ctx context.Context, action fleetapi.Action) error
	Commit(ctx context.Context) error
}
