// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Settings handles settings change coming from fleet and updates log level.
type Settings struct {
	log       *logger.Logger
	agentInfo *info.AgentInfo
	coord     *coordinator.Coordinator
}

// NewSettings creates a new Settings handler.
func NewSettings(
	log *logger.Logger,
	agentInfo *info.AgentInfo,
	coord *coordinator.Coordinator,
) *Settings {
	return &Settings{
		log:       log,
		agentInfo: agentInfo,
		coord:     coord,
	}
}

// Handle handles SETTINGS action.
func (h *Settings) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerSettings: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionSettings)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionSettings and received %T", a)
	}

	if !isSupportedLogLevel(action.LogLevel) {
		return fmt.Errorf("invalid log level, expected debug|info|warning|error and received '%s'", action.LogLevel)
	}

	lvl := logp.InfoLevel
	err := lvl.Unpack(action.LogLevel)
	if err != nil {
		return fmt.Errorf("failed to unpack log level: %w", err)
	}

	if err := h.agentInfo.SetLogLevel(action.LogLevel); err != nil {
		return fmt.Errorf("failed to update log level: %w", err)
	}

	if err := acker.Ack(ctx, a); err != nil {
		h.log.Errorf("failed to acknowledge SETTINGS action with id '%s'", action.ActionID)
	} else if err := acker.Commit(ctx); err != nil {
		h.log.Errorf("failed to commit acker after acknowledging action with id '%s'", action.ActionID)
	}

	h.log.Infof("Settings action done, setting agent log level to %s", lvl.String())
	return h.coord.SetLogLevel(ctx, lvl)
}

func isSupportedLogLevel(level string) bool {
	return level == "error" || level == "debug" || level == "info" || level == "warning"
}
