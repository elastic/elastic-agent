// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"log/slog"
	"os"
)

var (
	LogLevel = new(slog.LevelVar) // Info by default

	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: LogLevel}))
)

const (
	TraceLevel = slog.Level(-12)
	FatalLevel = slog.Level(12)
)
