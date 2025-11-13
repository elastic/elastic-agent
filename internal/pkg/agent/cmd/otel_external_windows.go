// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build otelexternal && windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/spf13/cobra"
)

const binaryName = "otelcol"

func newOtelCommandWithArgs(_ []string, _ *cli.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use: "otel",
		RunE: func(_ *cobra.Command, _ []string) error {
			executable := filepath.Join(paths.Components(), binaryName)
			cmd := exec.Command(executable, os.Args[2:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			err := cmd.Start()
			if err != nil {
				return fmt.Errorf("failed to start %s: %w", executable, err)
			}
			err = cmd.Wait()
			if err == nil {
				return nil
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("%s failed: %w", executable, err)
		},
	}
}
