// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package noop

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

// noopAcker is a noop acker.
// Methods of these acker do nothing.
type noopAcker struct{}

// New creates a new noop acker.
func New() acker.Acker {
	return &noopAcker{}
}

// Ack acknowledges action.
func (f *noopAcker) Ack(ctx context.Context, action fleetapi.Action) error {
	return nil
}

// Commit commits ack actions.
func (*noopAcker) Commit(ctx context.Context) error { return nil }
