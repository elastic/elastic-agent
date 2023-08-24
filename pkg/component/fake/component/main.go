// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/elastic/elastic-agent/pkg/component/fake/component/comp"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	logger := zerolog.New(os.Stderr).Level(zerolog.TraceLevel).With().Timestamp().Logger()
	ver := client.VersionInfo{
		Name:    comp.Fake,
		Version: "1.0",
		Meta: map[string]string{
			"input": comp.Fake,
		},
	}
	c, _, err := client.NewV2FromReader(os.Stdin, ver)
	if err != nil {
		return fmt.Errorf("failed to create GRPC client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	n := make(chan os.Signal, 1)
	signal.Notify(n, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer func() {
		signal.Stop(n)
		cancel()
	}()
	go func() {
		select {
		case <-n:
			cancel()
		case <-ctx.Done():
		}
	}()

	err = c.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start GRPC client: %w", err)
	}

	s := comp.NewStateManager(logger)
	for {
		select {
		case <-ctx.Done():
			return nil
		case change := <-c.UnitChanges():
			logger.Info().Msgf("Received change: %+v", change)
			if change.Unit != nil {
				logger.Info().Msgf("unit: %+v", change.Unit)
				if change.Unit.Expected().APMConfig != nil {
					logger.Info().Msgf("apmConfig: %+v", change.Unit.Expected().APMConfig)
				}
			}
			handleChange(logger, s, change)

		case err := <-c.Errors():
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "GRPC client error: %+v\n", err)
			}
		}
	}
}

func handleChange(logger zerolog.Logger, s *comp.StateManager, change client.UnitChanged) {
	if change.Unit != nil {
		u := change.Unit
		state, _, _ := u.State()
		logger.Info().
			Str("state", state.String()).
			Str("expectedState", u.Expected().State.String()).
			Msg("unit change received")
	} else {
		logger.Info().Msg("unit change received, but no unit on it")
	}

	switch change.Type {
	case client.UnitChangedAdded:
		s.Added(change.Unit)
	case client.UnitChangedModified:
		s.Modified(change)
	case client.UnitChangedRemoved:
		s.Removed(change.Unit)
	}
}
