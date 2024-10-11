// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/control/v2/client/wait"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func newPrivilegedCommandWithArgs(s []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "privileged",
		Short: "Switch installed Elastic Agent to run as privileged",
		Long: `This command converts the installed Elastic Agent from running unprivileged to running as privileged.

By default this command will ask or a confirmation before making this change. You can bypass the confirmation request
using the -f flag. This is not a zero downtime operation and will always stop the running Elastic Agent (if running).
It is possible that loss of metrics, logs, or data could occur during this window of time. The Elastic Agent
daemon will always be started (even if it was off to start). In the case that the Elastic Agent is already running
privileged it will still perform all the same work, including stopping and starting the Elastic Agent.
`,
		Args: cobra.ExactArgs(0),
		Run: func(c *cobra.Command, args []string) {
			if err := privilegedCmd(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolP("force", "f", false, "Do not prompt for confirmation")
	cmd.Flags().DurationP("daemon-timeout", "", 0, "Timeout waiting for Elastic Agent daemon restart after the change is applied (-1 = no wait)")

	return cmd
}

func privilegedCmd(streams *cli.IOStreams, cmd *cobra.Command) (err error) {
	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("unable to perform privileged command while checking for root/Administrator rights: %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("unable to perform privileged command, not executed with %s permissions", utils.PermissionUser)
	}

	topPath := paths.Top()
	daemonTimeout, _ := cmd.Flags().GetDuration("daemon-timeout")
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		confirm, err := cli.Confirm("This will restart the running Elastic Agent and convert it to run in privileged mode. Do you want to continue?", true)
		if err != nil {
			return fmt.Errorf("problem reading prompt response")
		}
		if !confirm {
			return fmt.Errorf("unprivileged switch was cancelled by the user")
		}
	}

	pt := install.CreateAndStartNewSpinner(streams.Out, "Converting Elastic Agent to privileged...")
	err = install.SwitchExecutingMode(topPath, pt, "", "")
	if err != nil {
		// error already adds context
		return err
	}

	// wait for the service
	if daemonTimeout >= 0 {
		pt.Describe("Waiting for running service")
		ctx := handleSignal(context.Background()) // allowed to be cancelled
		err = wait.ForAgent(ctx, daemonTimeout)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				pt.Describe("Cancelled waiting for running service")
				return nil
			}
			pt.Describe("Failed waiting for running service")
			return err
		}
		pt.Describe("Service is up and running")
	}

	return nil
}
