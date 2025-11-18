// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build otelexternal && !windows

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
// This temporarily has a '-component' prefix because the Elastic Agent can be build in two ways and this
// allows this to work with the way Elastic Agent is packaged without large changes that will be removed
// in the future once this becomes the default way.
const binaryName = "otelcol-component"

func newOtelCommandWithArgs(_ []string, _ *cli.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:                "otel",
		DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			executable := filepath.Join(paths.Home(), binaryName)
			args := []string{binaryName}
			args = append(args, os.Args[2:]...) // uses os.Args to preserve original args
			err := unix.Exec(executable, args, os.Environ())
			if err != nil {
				return fmt.Errorf("failed to exec %s: %w", executable, err)
			}
			return nil
		},
	}
}
