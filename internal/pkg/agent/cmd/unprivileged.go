// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/control/v2/client/wait"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	endpoint = "endpoint"
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

	// TODO(blakerouse): More work to get this working on macOS.
	// Need to switch the vault from keystore based to file based vault.
	if runtime.GOOS == "darwin" {
		return errors.New("unable to perform unprivileged on macOS (not supported)")
	}

	// cannot switch to unprivileged when Elastic Defend exists in the policy
	err = ensureNoElasticDefend()
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

func ensureNoElasticDefend() error {
	ctx := context.Background()
	l, err := newErrorLogger()
	if err != nil {
		return fmt.Errorf("failed to create error logger: %w", err)
	}
	comps, err := getComponentsFromPolicy(ctx, l, paths.ConfigFile(), 0)
	if err != nil {
		return fmt.Errorf("failed to create component model from policy: %w", err)
	}
	for _, comp := range comps {
		if comp.InputSpec != nil && comp.InputSpec.InputType == endpoint {
			return errors.New("unable to switch to unprivileged mode because Elastic Defend exists in the policy")
		}
	}
	return nil
}
