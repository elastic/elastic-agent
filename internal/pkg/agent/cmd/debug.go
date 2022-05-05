package cmd

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const flagPort = "port"

func newDebugCommand(streams *cli.IOStreams, getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Debug helps to debug the Elastic Agent and the applications it runs.",
		Long:  "Debug helps to debug the Elastic Agent and the applications it runs.",
		Run: func(c *cobra.Command, args []string) {
			err := debugCmd(streams, c, args, getDiagnostics)
			if err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				return
			}
		},
	}

	cmd.Flags().StringP(flagPort, "p", "4242", "The port the Delve server will listen on")

	return cmd
}

func debugCmd(s *cli.IOStreams, c *cobra.Command, args []string, getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)) error {
	const cmd = "\t%s:\tdlv --listen=:%s --headless=true --api-version=2 --accept-multiclient attach %d\n"

	tw := tabwriter.NewWriter(s.Out, 4, 1, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintf(tw, "\n")

	diag, err := getDiagnostics(context.Background())
	if err != nil {
		return fmt.Errorf("could not get debug (diagnostics) info: %w", err)
	}

	port, err := c.Flags().GetString(flagPort)
	if err != nil {
		fmt.Fprintf(s.Err, fmt.Errorf("get flag error: %v", err).Error())
	}

	fmt.Fprintf(tw, "PIDs:\n")
	fmt.Fprintf(tw, "\telastic-agent: %d\n", diag.AgentInfo.PID)
	for _, app := range diag.ProcMetas {
		fmt.Fprintf(tw, "\t%s: %d\n", app.Name, app.PID)
	}
	fmt.Fprintf(tw, "\n")

	fmt.Fprintf(tw, "Delve commands:\n")
	fmt.Fprintf(tw, cmd, "elastic-agent", port, diag.AgentInfo.PID)
	for _, app := range diag.ProcMetas {
		fmt.Fprintf(tw, cmd, app.Name, port, app.PID)
	}
	return nil
}
