// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"flag"
	"os"

	"github.com/spf13/cobra"

	// import logp flags
	_ "github.com/elastic/elastic-agent-libs/logp/configure"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/agentrun"
	applyflavor "github.com/elastic/elastic-agent/internal/pkg/agent/cmd/apply_flavor"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/common"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/component"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/container"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/inspect"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/install"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/logs"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/otel"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/status"
	switchcmd "github.com/elastic/elastic-agent/internal/pkg/agent/cmd/switch"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/uninstall"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/watch"
	"github.com/elastic/elastic-agent/internal/pkg/basecmd"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/version"
)

// NewCommand returns the default command for the agent.
func NewCommand() *cobra.Command {
	return NewCommandWithArgs(os.Args, cli.NewIOStreams())
}

// NewCommandWithArgs returns a new agent with the flags and the subcommand.
func NewCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use: "elastic-agent [subcommand]",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "container" {
				// need to initialize container and try to chown agent-related paths
				// before tryContainerLoadPaths as this will try to read/write from
				// the agent state dir which might not have proper permissions when
				// running inside a container
				container.InitContainer(streams)
			}

			return common.TryContainerLoadPaths()
		},
	}

	// Init version information contained in package version file
	if isOtel := len(args) > 1 && args[1] == "otel"; !isOtel {
		err := version.InitVersionError()
		if err != nil {
			cmd.PrintErrf("Error initializing version information: %v\n", err)
		}
	}

	// path flags
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.home"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.home.unversioned"))
	// hidden used internally by container subcommand
	cmd.PersistentFlags().MarkHidden("path.home.unversioned") //nolint:errcheck // it's hidden
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.config"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("c"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("config"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.logs"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.downloads"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.socket"))

	// logging flags
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("v"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("e"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("d"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("environment"))

	// sub-commands
	run := agentrun.NewRunCommandWithArgs(args, streams)
	cmd.AddCommand(basecmd.NewDefaultCommandsWithArgs(args, streams)...)
	cmd.AddCommand(run)

	cmd.AddCommand(install.NewInstallCommandWithArgs(args, streams))
	cmd.AddCommand(uninstall.NewUninstallCommandWithArgs(args, streams))
	cmd.AddCommand(upgrade.NewUpgradeCommandWithArgs(args, streams))
	cmd.AddCommand(install.NewEnrollCommandWithArgs(args, streams))
	cmd.AddCommand(inspect.NewInspectCommandWithArgs(args, streams))
	cmd.AddCommand(switchcmd.NewPrivilegedCommandWithArgs(args, streams))
	cmd.AddCommand(switchcmd.NewUnprivilegedCommandWithArgs(args, streams))
	cmd.AddCommand(watch.NewWatchCommandWithArgs(args, streams))
	cmd.AddCommand(container.NewContainerCommand(args, streams))
	cmd.AddCommand(status.NewStatusCommand(args, streams))
	cmd.AddCommand(diagnostics.NewDiagnosticsCommand(args, streams))
	cmd.AddCommand(component.NewComponentCommandWithArgs(args, streams))
	cmd.AddCommand(logs.NewLogsCommandWithArgs(args, streams))
	cmd.AddCommand(otel.NewOtelCommandWithArgs(args, streams))
	cmd.AddCommand(applyflavor.NewApplyFlavorCommandWithArgs(args, streams))

	// windows special hidden sub-command (only added on Windows)
	reexec := reexec.NewReExecWindowsCommand(args, streams)
	if reexec != nil {
		cmd.AddCommand(reexec)
	}
	cmd.Run = run.Run
	cmd.RunE = run.RunE

	return cmd
}
