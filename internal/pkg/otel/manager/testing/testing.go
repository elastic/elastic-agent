// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
)

func main() {
	var shutdownDelay time.Duration
	var err error
	shutdownDelayEnvVar := os.Getenv("TEST_SUPERVISED_COLLECTOR_DELAY")
	if shutdownDelayEnvVar != "" {
		shutdownDelay, _ = time.ParseDuration(shutdownDelayEnvVar)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if panicEnvVar := os.Getenv("TEST_SUPERVISED_COLLECTOR_PANIC"); panicEnvVar != "" {
		panicDelay, err := time.ParseDuration(panicEnvVar)
		if err != nil {
			// fallback to 3 seconds
			panicDelay = 3 * time.Second
		}
		time.AfterFunc(panicDelay, func() {
			panic("test panic")
		})
	}

	err = cmd.RunCollector(ctx, nil, true, "debug")
	if err == nil || errors.Is(err, context.Canceled) {
		if shutdownDelay > 0 {
			<-time.After(shutdownDelay)
		}
		os.Exit(0)
	}
	if shutdownDelay > 0 {
		<-time.After(shutdownDelay)
	}
	os.Exit(1)
}
