package cmd

import (
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/spf13/cobra"
)

// NewCommandWithArgs returns a new edot with the flags and the subcommand.
func NewCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use: "edot [subcommand]",
	}

	otel := newOtelCommandWithArgs(args, streams)
	cmd.AddCommand(otel)

	cmd.Run = otel.Run
	return cmd
}
