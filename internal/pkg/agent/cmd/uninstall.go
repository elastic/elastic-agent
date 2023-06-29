// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func newUninstallCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Elastic Agent from this system",
		Long: `This command uninstalls the Elastic Agent permanently from this system.  The system's service manager will no longer manage Elastic agent.

Unless -f is used this command will ask confirmation before performing removal.
`,
		Run: func(c *cobra.Command, _ []string) {
			if err := uninstallCmd(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolP("force", "f", false, "Force overwrite the current and do not prompt for confirmation")
	cmd.Flags().String("uninstall-token", "", "Token that protects Agent with Endpoint from uninstall")

	return cmd
}

func uninstallCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("unable to perform command while checking for administrator rights, %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("unable to perform command, not executed with %s permissions", utils.PermissionUser)
	}
	status, reason := install.Status(paths.Top())
	if status == install.NotInstalled {
		return fmt.Errorf("not installed")
	}
	if status == install.Installed && !info.RunningInstalled() {
		return fmt.Errorf("can only be uninstalled by executing the installed Elastic Agent at: %s", install.ExecutablePath(paths.Top()))
	}

	force, _ := cmd.Flags().GetBool("force")
	uninstallToken, _ := cmd.Flags().GetString("uninstall-token")
	if status == install.Broken {
		if !force {
			fmt.Fprintf(streams.Out, "Elastic Agent is installed but currently broken: %s\n", reason)
			confirm, err := cli.Confirm(fmt.Sprintf("Continuing will uninstall the broken Elastic Agent at %s. Do you want to continue?", paths.Top()), true)
			if err != nil {
				return fmt.Errorf("problem reading prompt response")
			}
			if !confirm {
				return fmt.Errorf("uninstall was cancelled by the user")
			}
		}
	} else {
		if !force {
			confirm, err := cli.Confirm(fmt.Sprintf("Elastic Agent will be uninstalled from your system at %s. Do you want to continue?", paths.Top()), true)
			if err != nil {
				return fmt.Errorf("problem reading prompt response")
			}
			if !confirm {
				return fmt.Errorf("uninstall was cancelled by the user")
			}
		}
	}

	err = install.Uninstall(paths.ConfigFile(), paths.Top(), uninstallToken)
	if err != nil {
		return err
	}
	fmt.Fprintf(streams.Out, "Elastic Agent has been uninstalled.\n")

	_ = install.RemovePath(paths.Top())
	return nil
}
