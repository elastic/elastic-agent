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
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/client/wait"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func newUnprivilegedCommandWithArgs(s []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unprivileged",
		Short: "Switch installed Elastic Agent to run as unprivileged",
		Long: `This command converts the installed Elastic Agent from running privileged to running as unprivileged.

By default this command will ask or a confirmation before making this change. You can bypass the confirmation request
using the -f flag. This is not a zero downtime operation and will always stop the running Elastic Agent (if running).
It is possible that loss of metrics, logs, or data could occur during this window of time. The Elastic Agent
daemon will always be started (even if it was off to start). In the case that the Elastic Agent is already running
unprivileged it will still perform all the same work, including stopping and starting the Elastic Agent.
`,
		Args: cobra.ExactArgs(0),
		Run: func(c *cobra.Command, args []string) {
			if err := unprivilegedCmd(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolP("force", "f", false, "Do not prompt for confirmation")
	cmd.Flags().DurationP("daemon-timeout", "", 0, "Timeout waiting for Elastic Agent daemon restart after the change is applied (-1 = no wait)")

	return cmd
}

func unprivilegedCmd(streams *cli.IOStreams, cmd *cobra.Command) (err error) {
	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("unable to perform unprivileged command while checking for root/Administrator rights: %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("unable to perform unprivileged command, not executed with %s permissions", utils.PermissionUser)
	}

	// cannot switch to unprivileged when service components have issues
	err = ensureNoServiceComponentIssues()
	if err != nil {
		// error already adds context
		return err
	}

	topPath := paths.Top()
	daemonTimeout, _ := cmd.Flags().GetDuration("daemon-timeout")
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		confirm, err := cli.Confirm("This will restart the running Elastic Agent and convert it to run in unprivileged mode. Do you want to continue?", true)
		if err != nil {
			return fmt.Errorf("problem reading prompt response")
		}
		if !confirm {
			return fmt.Errorf("unprivileged switch was cancelled by the user")
		}
	}

	pt := install.CreateAndStartNewSpinner(streams.Out, "Converting Elastic Agent to unprivileged...")
	err = install.SwitchExecutingMode(topPath, pt, install.ElasticUsername, install.ElasticGroupName)
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

func ensureNoServiceComponentIssues() error {
	ctx := context.Background()
	l, err := newErrorLogger()
	if err != nil {
		return fmt.Errorf("failed to create error logger: %w", err)
	}
	// this forces the component calculation to always compute with no root
	// this allows any runtime preventions to error for a component when it has a no root support
	comps, err := getComponentsFromPolicy(ctx, l, paths.ConfigFile(), 0, forceNonRoot)
	if err != nil {
		return fmt.Errorf("failed to create component model from policy: %w", err)
	}
	var errs []error
	for _, comp := range comps {
		if comp.InputSpec == nil {
			// no spec (safety net)
			continue
		}
		if comp.InputSpec.Spec.Service == nil {
			// not a service component, allowed to exist (even if it needs root)
			continue
		}
		if comp.Err != nil {
			// service component has an error (most likely because it cannot run without root)
			errs = append(errs, fmt.Errorf("%s -> %w", comp.ID, comp.Err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("unable to switch to unprivileged mode due to the following service based components having issues: %w", errors.Join(errs...))
	}
	return nil
}

func forceNonRoot(detail component.PlatformDetail) component.PlatformDetail {
	detail.User.Root = false
	return detail
}
