// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package loggertest

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// New creates a testing logger that buffers the logs in memory and
// logs in debug level. Check observer.ObservedLogs for more details.
func New(name string) (*logger.Logger, *observer.ObservedLogs) {
	core, obs := observer.New(zapcore.DebugLevel)

	log := logp.NewLogger(
		name,
		zap.WrapCore(func(in zapcore.Core) zapcore.Core {
			return zapcore.NewTee(in, core)
		}))

	return log, obs
}

// PrintObservedLogs formats and prints all log entries in logs, one at a time
// using printFn.
func PrintObservedLogs(logs []observer.LoggedEntry, printFn func(a ...any)) {
	for _, l := range logs {
		msg := fmt.Sprintf("[%s] %s", l.Level, l.Message)
		for k, v := range l.ContextMap() {
			msg += fmt.Sprintf(" %s=%v", k, v)
		}
		printFn(msg)
	}
}
