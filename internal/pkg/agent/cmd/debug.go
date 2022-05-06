package cmd

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const flagPort = "port"
const flagLocal = "local"

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
	cmd.Flags().BoolP(flagLocal, "l", false, "Outputs the Delve command for local debug")

	return cmd
}

func debugCmd(s *cli.IOStreams, c *cobra.Command, args []string, getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)) error {
	const cmdRemote = "\t%s:\tdlv --listen=:%s --headless=true --api-version=2 --accept-multiclient attach %d\n"
	const cmdLocal = "\t%s:\tdlv attach %d\n"
	var sprintCMD func(name string, pid int64) string

	tw := tabwriter.NewWriter(s.Out, 4, 1, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintf(tw, "\n")

	diag, err := getDiagnostics(context.Background())
	if err != nil {
		return fmt.Errorf("could not get debug (diagnostics) info: %w", err)
	}

	flags := c.Flags()
	local, err := flags.GetBool(flagLocal)
	if err != nil {
		fmt.Fprintf(s.Err, fmt.Errorf("could not get flag %q error: %v", flagLocal, err).Error())
		return nil
	}
	if local {
		sprintCMD = func(name string, pid int64) string {
			return fmt.Sprintf(cmdLocal, name, pid)
		}
	} else {
		port, err := c.Flags().GetString(flagPort)
		if err != nil {
			fmt.Fprintf(s.Err, fmt.Errorf("could not get flag %q error: %v", flagPort, err).Error())
			return nil
		}
		sprintCMD = func(name string, pid int64) string {
			return fmt.Sprintf(cmdRemote, name, port, pid)
		}
	}

	fmt.Fprintf(tw, "PIDs:\n")
	fmt.Fprintf(tw, "\telastic-agent: \t%d\n", diag.AgentInfo.PID)
	for _, app := range diag.ProcMetas {
		fmt.Fprintf(tw, "\t%s: \t%d\n", app.Name, app.PID)
	}
	fmt.Fprintf(tw, "\n")

	fmt.Fprintf(tw, "Delve commands:\n")
	fmt.Fprintf(tw, sprintCMD("elastic-agent", diag.AgentInfo.PID))

	for _, app := range diag.ProcMetas {
		fmt.Fprintf(tw, sprintCMD(app.Name, app.PID))
	}
	return nil
}
