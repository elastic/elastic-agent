// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
