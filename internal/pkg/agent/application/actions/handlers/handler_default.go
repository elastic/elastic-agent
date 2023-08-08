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

// Default is a default handler.
type Default struct {
	log *logger.Logger
}

// NewDefault creates a new Default handler.
func NewDefault(log *logger.Logger) *Default {
	return &Default{
		log: log,
	}
}

// Handle is a default handler, no action is taken.
func (h *Default) Handle(_ context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Errorf("HandlerDefault: action '%+v' received", a)
	return nil
}
