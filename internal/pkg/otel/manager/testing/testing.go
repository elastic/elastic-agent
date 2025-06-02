// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"errors"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var err error
	defaultCfg := logger.DefaultLoggingConfig()
	defaultEventLogCfg := logger.DefaultEventLoggingConfig()

	defaultCfg.ToStderr = true
	defaultCfg.ToFiles = false
	defaultEventLogCfg.ToFiles = false
	defaultEventLogCfg.ToStderr = true
	defaultCfg.Level = logger.DefaultLogLevel

	baseLogger, err := logger.NewFromConfig("edot", defaultCfg, defaultEventLogCfg, false)
	if err != nil {
		panic(err)
	}

	err = otel.RunSupervisedCollector(ctx, baseLogger, os.Stdin)
	if err == nil || errors.Is(err, context.Canceled) {
		os.Exit(0)
	}
	os.Exit(1)
}
