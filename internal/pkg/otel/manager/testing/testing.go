// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/edot/cmd"
)

// This is a test binary used by the OTEL manager unit tests.
<<<<<<< HEAD:internal/pkg/otel/manager/testing/testing.go
// It launches a supervised collector using cmd.RunCollector, and can be
// configured via env vars to simulate different scenarios:
=======
// It mirrors the behavior of the real EDOT binary (internal/edot/main.go)
// but registers only the minimal OTel components required by the tests
// (see components.go) instead of the full EDOT component set.
// It can be configured via env vars to simulate different scenarios:
>>>>>>> a2ff291fb (Refactor edot commands to allow component factory injection (#13906)):internal/edot/testing/testing.go
//   - TEST_SUPERVISED_COLLECTOR_PANIC: triggers a panic after the given delay,
//     allowing tests to verify the manager's panic/restart behavior.
//   - TEST_SUPERVISED_COLLECTOR_DELAY: delays process shutdown by the given
//     duration, letting tests observe graceful termination handling.
//
// The binary exits with code 0 on a successful collector run (or when canceled),
// and code 1 if the collector returns an error.
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

<<<<<<< HEAD:internal/pkg/otel/manager/testing/testing.go
	monitoringURL := os.Getenv("TEST_SUPERVISED_COLLECTOR_MONITORING_URL")

	err = cmd.RunCollector(ctx, nil, true, "debug", monitoringURL)
	if err != nil && !errors.Is(err, context.Canceled) {
		logp.NewLogger("").Fatal("collector server run finished with error: %v", err)
=======
	collectorCmd := cmd.NewOtelCommandWithArgs(os.Args, cli.NewIOStreams(), testComponents)
	err = collectorCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
>>>>>>> a2ff291fb (Refactor edot commands to allow component factory injection (#13906)):internal/edot/testing/testing.go
	}

	if shutdownDelay > 0 {
		<-time.After(shutdownDelay)
	}
}
