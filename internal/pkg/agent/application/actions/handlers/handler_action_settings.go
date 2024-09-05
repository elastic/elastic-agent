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
type Settings struct {
	log              *logger.Logger
	agentInfo        info.Agent
	fallbackLogLevel *logp.Level
	logLevelSetter   logLevelSetter
}

// NewSettings creates a new Settings handler.
func NewSettings(
	log *logger.Logger,
	agentInfo info.Agent,
	logLevelSetter logLevelSetter,
) *Settings {
	return &Settings{
		log:            log,
		agentInfo:      agentInfo,
		logLevelSetter: logLevelSetter,
	}
}

// Handle handles SETTINGS action.
func (h *Settings) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerSettings: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionSettings)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionSettings and received %T", a)
	}

	logLevel := action.Data.LogLevel
	return h.handleLogLevel(ctx, logLevel, acker, action)
}

func (h *Settings) handleLogLevel(ctx context.Context, logLevel string, acker acker.Acker, action *fleetapi.ActionSettings) error {
	var lvl *logp.Level
	if logLevel != clearLogLevelValue {
		if !isSupportedLogLevel(logLevel) {
			return fmt.Errorf("invalid log level, expected debug|info|warning|error and received '%s'", logLevel)
		}

		// parse loglvl from the string
		parsedLvl := logp.InfoLevel
		err := parsedLvl.Unpack(logLevel)
		if err != nil {
			return fmt.Errorf("failed to unpack log level: %w", err)
		}
		lvl = &parsedLvl
	}
	if err := h.agentInfo.SetLogLevel(ctx, logLevel); err != nil {
		return fmt.Errorf("failed to update log level: %w", err)
	}

	if err := acker.Ack(ctx, action); err != nil {
		h.log.Errorf("failed to acknowledge SETTINGS action with id '%s'", action.ActionID)
	} else if err := acker.Commit(ctx); err != nil {
		h.log.Errorf("failed to commit acker after acknowledging action with id '%s'", action.ActionID)
	}

	if lvl != nil {
		h.log.Infof("Settings action done, setting agent log level to %s", logLevel)
		return h.logLevelSetter.SetLogLevel(ctx, lvl)
	}

	if h.fallbackLogLevel != nil {
		h.log.Infof("Settings action done, setting agent log level to policy default %s", h.fallbackLogLevel)
		// use fallback log level
		return h.logLevelSetter.SetLogLevel(ctx, h.fallbackLogLevel)
	}

	// use default log level
	defaultLogLevel := logger.DefaultLogLevel
	h.log.Infof("Settings action done, setting agent log level to default %s", defaultLogLevel)
	return h.logLevelSetter.SetLogLevel(ctx, &defaultLogLevel)
}

// SetLogLevel is used to set the fallback log level
// It propagates this log level in case there's no log level set for this specific agent
func (h *Settings) SetLogLevel(ctx context.Context, lvl *logp.Level) error {
	if lvl != nil && !isSupportedLogLevel(lvl.String()) {
		return fmt.Errorf("invalid log level, expected debug|info|warning|error and received '%s'", lvl.String())
	}

	h.fallbackLogLevel = lvl
	rawLogLevel := h.agentInfo.RawLogLevel()
	h.log.Debugf("received fallback loglevel %s, raw loglevel %s", lvl, rawLogLevel)
	if rawLogLevel == "" && lvl != nil {
		h.log.Debugf("setting log level %s", lvl)
		// set the runtime log level only if we don't have one set for the specific agent
		return h.logLevelSetter.SetLogLevel(ctx, lvl)
	}
	return nil
}

func isSupportedLogLevel(level string) bool {
	return level == "error" || level == "debug" || level == "info" || level == "warning"
}
