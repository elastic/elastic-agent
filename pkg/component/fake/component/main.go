// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"errors"
	"flag"
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
	// The agent passes flags like "-E path.data=..." to component binaries.
	// Use a custom FlagSet with ContinueOnError so unknown flags are silently
	// ignored instead of causing the process to exit.
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	ignoreSIGTERM := fs.Bool("sigterm-ignore", false, "ignore SIGTERM signal for testing zombie process handling")
	noPdeathsig := fs.Bool("clear-pdeathsig", false, "clear parent-death signal so process survives parent exit (Linux testing only)")
	fs.SetOutput(io.Discard)
	_ = fs.Parse(os.Args[1:])

	if *noPdeathsig {
		clearPdeathsig()
	}

	err := run(*ignoreSIGTERM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run(ignoreSIGTERM bool) error {
	logger := zerolog.New(os.Stderr).Level(zerolog.TraceLevel).With().Timestamp().Logger()
	ver := client.VersionInfo{
		Name: comp.Fake,
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
	if ignoreSIGTERM {
		signal.Ignore(syscall.SIGTERM)
		signal.Notify(n, syscall.SIGINT, syscall.SIGQUIT)
	} else {
		signal.Notify(n, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	}
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
