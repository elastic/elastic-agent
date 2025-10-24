// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/utils/strings/slices"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

func newOtelCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:                "otel",
		Short:              "Start the Elastic Agent in otel mode",
		Long:               "This command starts the Elastic Agent in otel mode.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			elasticAgentExecutableDir, err := paths.RetrieveExecutableDir()
			if err != nil {
				return fmt.Errorf("failed to get the path of edot executable: %w", err)
			}

			edotExecutable := filepath.Join(elasticAgentExecutableDir, "edot")
			if goruntime.GOOS == "windows" {
				edotExecutable += ".exe"
			}

			// Create the arguments
			var edotArgs []string
			if len(os.Args) > 1 {
				edotArgs = os.Args[1:]
			}

			// TODO(splitting-edot): find a way to decouple properly elastic-agent flags from edot flags
			edotArgs = slices.Filter(nil, edotArgs, func(arg string) bool {
				switch arg {
				case "-c", "-v", "-e", "-d":
					return false
				default:
					return true
				}
			})

			proc, err := process.Start(
				edotExecutable,
				process.WithContext(cmd.Context()),
				process.WithArgs(edotArgs),
				process.WithEnv(os.Environ()),
				process.WithCmdOptions(func(c *exec.Cmd) error {
					c.Stdout = os.Stdout
					c.Stderr = os.Stderr
					return nil
				}))
			if err != nil {
				return fmt.Errorf("failed to start edot: %w", err)
			}

			// Wait for the command to finish
			processState, err := proc.Process.Wait()
			if err != nil {
				return fmt.Errorf("failed to wait for edot: %w", err)
			}

			os.Exit(processState.ExitCode())
			return nil
		},
		PreRun: func(c *cobra.Command, args []string) {
			// hide inherited flags not to bloat help with flags not related to otel
			hideInheritedFlags(c)
		},
		SilenceUsage: true,
	}

	return cmd
}

func hideInheritedFlags(c *cobra.Command) {
	c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		f.Hidden = true
	})
}
