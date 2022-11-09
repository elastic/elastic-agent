// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Unknown is a handler for unrecognized actions.
type Unknown struct {
	log *logger.Logger
}

// NewUnknown creates a new Unknown handler.
func NewUnknown(log *logger.Logger) *Unknown {
	return &Unknown{
		log: log,
	}
}

// Handle handles unknown actions, no action is taken.
func (h *Unknown) Handle(_ context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Errorf("HandlerUnknown: action '%+v' received", a)
	return nil
}
