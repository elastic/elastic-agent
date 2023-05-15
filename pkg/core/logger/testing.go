// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent-libs/logp"
)

// NewTesting creates a testing logger that buffers the logs in memory and
// logs in debug level. Check observer.ObservedLogs for more details.
func NewTesting(name string) (*Logger, *observer.ObservedLogs) {
	core, obs := observer.New(zapcore.DebugLevel)

	logger := logp.NewLogger(
		name,
		zap.WrapCore(func(in zapcore.Core) zapcore.Core {
			return zapcore.NewTee(in, core)
		}))
	return logger, obs
}
