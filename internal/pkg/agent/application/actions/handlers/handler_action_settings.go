// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const clearLogLevelValue = ""

// Settings handles settings change coming from fleet and updates log level.
type SettingsHandler struct {
	log                   *logger.Logger
	agentInfo             info.Agent
	runtimeLogLevelSetter logLevelSetter
}

// NewSettingsHandler creates a new SettingsHandler.
func NewSettingsHandler(
	log *logger.Logger,
	agentInfo info.Agent,
	runtimeLogLevelSetter logLevelSetter,
) *SettingsHandler {
	return &SettingsHandler{
		log:                   log,
		agentInfo:             agentInfo,
		runtimeLogLevelSetter: runtimeLogLevelSetter,
	}
}

// Handle handles SETTINGS action.
func (h *SettingsHandler) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerSettings: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionSettings)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionSettings and received %T", a)
	}

	logLevel := action.Data.LogLevel
	return h.handleLogLevel(ctx, logLevel, acker, action)
}

func (h *SettingsHandler) handleLogLevel(ctx context.Context, logLevel string, acker acker.Acker, action *fleetapi.ActionSettings) error {
	if logLevel != clearLogLevelValue {
		var logLevelOverride logp.Level
		if err := logLevelOverride.Unpack(logLevel); err != nil {
			return fmt.Errorf("failed to unpack override log level %q: %w", logLevel, err)
		}
	}
	if err := h.agentInfo.SetLogLevelOverride(ctx, logLevel); err != nil {
		return fmt.Errorf("failed to persist log level override: %w", err)
	}

	if err := acker.Ack(ctx, action); err != nil {
		h.log.Errorf("failed to acknowledge SETTINGS action with id '%s'", action.ActionID)
	} else if err := acker.Commit(ctx); err != nil {
		h.log.Errorf("failed to commit acker after acknowledging action with id '%s'", action.ActionID)
	}

	// Push the effective log level to the runtime.
	var logLevelRuntime logp.Level
	logLevelRuntimeStr := h.agentInfo.GetLogLevelRuntime()
	if err := logLevelRuntime.Unpack(logLevelRuntimeStr); err != nil {
		return fmt.Errorf("failed to unpack runtime log level %q: %w", logLevelRuntimeStr, err)
	}
	h.log.Infof("Settings action done, setting agent log level to %s", logLevelRuntime)
	return h.runtimeLogLevelSetter.SetLogLevel(ctx, &logLevelRuntime)
}
