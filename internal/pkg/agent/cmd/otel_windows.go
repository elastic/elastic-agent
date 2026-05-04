// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/core/process"
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

			info, err := process.Start(executable,
				process.WithArgs(cmdArgs),
				process.WithCmdOptions(func(c *exec.Cmd) error {
					c.Stdout = os.Stdout
					c.Stderr = os.Stderr
					c.Stdin = os.Stdin
					return nil
				}),
			)

			if err != nil {

				return fmt.Errorf("failed to start %s: %w", executable, err)
			}
			processState, err := info.Process.Wait()
			if err != nil {
				return fmt.Errorf("failed to wait for %s: %w", executable, err)
			}
			os.Exit(processState.ExitCode())
			return nil
		},
	}
}
