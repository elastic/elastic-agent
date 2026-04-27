// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

// binaryName is the name of the executable to run
const binaryName = "elastic-otel-collector.exe"

func newOtelCommandWithArgs(_ []string, _ *cli.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:                "otel",
		DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, cmdArgs []string) error {
			executable := filepath.Join(paths.Components(), binaryName)

			// Absorb console-control signals so the Go runtime suppresses
			// Windows' default handler. We don't act on the signals here:
			// the collector child shares this process's group (no
			// CREATE_NEW_PROCESS_GROUP), inherits stdio, and receives the
			// same Ctrl events directly from the kernel — exactly as if
			// we'd done unix.Exec on a non-Windows platform. Our only job
			// is to stay alive long enough for the collector to finish its
			// own graceful shutdown, then propagate its exit code.
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
			defer signal.Stop(sigCh)
			go func() {
				for range sigCh {
					// drain only — the collector handles shutdown
				}
			}()

			cmd := exec.Command(executable, cmdArgs...) //nolint:noctx // signal handling is via os.Signal, not ctx
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			err := cmd.Run()
			if err == nil {
				return nil
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("failed to run %s: %w", executable, err)
		},
	}
}
