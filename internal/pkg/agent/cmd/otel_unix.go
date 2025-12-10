// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

// binaryName is the name of the executable to run
const binaryName = "elastic-otel-collector"

func newOtelCommandWithArgs(_ []string, _ *cli.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:                "otel",
		DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, cmdArgs []string) error {
			executable := filepath.Join(paths.Components(), binaryName)
			args := []string{binaryName}
			args = append(args, cmdArgs...)
			err := unix.Exec(executable, args, os.Environ())
			if err != nil {
				return fmt.Errorf("failed to exec %s: %w", executable, err)
			}
			return nil
		},
	}
}
