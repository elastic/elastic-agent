// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentrun

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent-libs/service"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/common"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const (
	flagInstallDevelopment = "develop"
)

func NewRunCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the Elastic Agent",
		Long:  "This command starts the Elastic Agent.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			isDevelopmentMode, _ := cmd.Flags().GetBool(flagInstallDevelopment)
			if isDevelopmentMode {
				fmt.Fprintln(streams.Out, "Development installation mode enabled; this is an experimental feature.")
				// For now, development mode only makes the agent behave as if it was running in a namespace to allow
				// multiple agents on the same machine.
				paths.SetInstallNamespace(paths.DevelopmentNamespace)
			}

			// done very early so the encrypted store is never used. Always done in development mode to remove the need to be root.
			disableEncryptedStore, _ := cmd.Flags().GetBool("disable-encrypted-store")
			disableEncyption(disableEncryptedStore, isDevelopmentMode)

			fleetInitTimeout, _ := cmd.Flags().GetDuration("fleet-init-timeout")
			testingMode, _ := cmd.Flags().GetBool("testing-mode")
			if err := runService(testingMode, fleetInitTimeout); err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, common.TroubleshootMessage())
				common.LogExternal(fmt.Sprintf("%s run failed: %s", paths.BinaryName, err))
				return err
			}
			return nil
		},
	}

	// --disable-encrypted-store only has meaning on Mac OS, and it disables the encrypted disk store
	// feature of the Elastic Agent. On Mac OS root privileges are required to perform the disk
	// store encryption, by setting this flag it disables that feature and allows the Elastic Agent to
	// run as non-root.
	//
	// Deprecated: MacOS can be run/installed without root privileges
	cmd.Flags().Bool("disable-encrypted-store", false, "Disable the encrypted disk storage (Only useful on Mac OS)")
	_ = cmd.Flags().MarkHidden("disable-encrypted-store")
	_ = cmd.Flags().MarkDeprecated("disable-encrypted-store", "agent on Mac OS can be run/installed without root privileges, see elastic-agent install --help")

	// --testing-mode is a hidden flag that spawns the Elastic Agent in testing mode
	// it is hidden because we really don't want users to execute Elastic Agent to run
	// this way, only the integration testing framework runs the Elastic Agent in this mode
	cmd.Flags().Bool("testing-mode", false, "Run with testing mode enabled")

	cmd.Flags().Duration("fleet-init-timeout", common.EnvTimeout(fleetInitTimeoutName), " Sets the initial timeout when starting up the fleet server under agent")
	_ = cmd.Flags().MarkHidden("testing-mode")

	cmd.Flags().Bool(flagRunDevelopment, false, "Run agent in development mode. Allows running when there is already an installed Elastic Agent. (experimental)")
	_ = cmd.Flags().MarkHidden(flagRunDevelopment) // For internal use only.

	return cmd
}

func runService(testingMode bool, fleetInitTimeout time.Duration) error {
	// Windows: Mark service as stopped.
	// After this is run, the service is considered by the OS to be stopped.
	// This must be the first deferred cleanup task (last to execute).
	defer func() {
		service.NotifyTermination()
		service.WaitExecutionDone()
	}()

	service.BeforeRun()
	defer service.Cleanup()

	return Run(nil, testingMode, fleetInitTimeout)
}
