// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Command workflow-runner is an Elastic Agent component that performs Kibana
// Workflow HTTP steps from the network the agent runs in.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/internal/pkg/workflowrunner"
)

const componentName = "workflow-runner"

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	logger := zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().Timestamp().Logger()

	dataDir, err := dataPath(os.Args[1:])
	if err != nil {
		return err
	}
	store, err := workflowrunner.OpenStore(dataDir)
	if err != nil {
		return fmt.Errorf("opening completed-action store: %w", err)
	}

	ver := client.VersionInfo{
		Name: componentName,
		Meta: map[string]string{"input": workflowrunner.ActionName},
	}
	c, _, err := client.NewV2FromReader(os.Stdin, ver)
	if err != nil {
		return fmt.Errorf("creating control protocol client: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	if err := c.Start(ctx); err != nil {
		return fmt.Errorf("starting control protocol client: %w", err)
	}
	defer c.Stop()

	m := workflowrunner.NewManager(logger, workflowrunner.NewExecutor(), store)
	for {
		select {
		case <-ctx.Done():
			return nil
		case change := <-c.UnitChanges():
			m.HandleChange(change)
		case err := <-c.Errors():
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				logger.Error().Err(err).Msg("control protocol error")
			}
		}
	}
}

// dataPath returns the directory the agent assigned to this component through
// "-E path.data=<dir>", falling back to the working directory the agent starts it in.
func dataPath(args []string) (string, error) {
	const prefix = "path.data="
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-E" && i+1 < len(args) {
			i++
			arg = args[i]
		} else {
			arg = strings.TrimPrefix(arg, "-E")
		}
		if v, ok := strings.CutPrefix(arg, prefix); ok && v != "" {
			return v, nil
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("determining data directory: %w", err)
	}
	return dir, nil
}
