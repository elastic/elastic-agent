package cmd

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const flagPort = "port"
const flagLocal = "local"

const (
	cmdRemote    = "dlv --listen=:%s --headless=true --api-version=2 --accept-multiclient attach %d"
	cmdLocal     = "dlv attach %d"
	formatRemote = "\t%s:\t" + cmdRemote + "\n"
	formatLocal  = "\t%s:\t" + cmdLocal + "\n"
)

type debugData struct {
	name string
	pid  int64
}

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

	cmd.PersistentFlags().StringP(flagPort, "p", "4242", "The port the Delve server will listen on")
	cmd.PersistentFlags().BoolP(flagLocal, "l", false, "Outputs the Delve command for local debug")

	cmd.AddCommand(newDebugRunCommand(streams, getDiagnostics))
	return cmd
}

func debugCmd(s *cli.IOStreams, c *cobra.Command, args []string, getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)) error {
	tw := tabwriter.NewWriter(s.Out, 4, 1, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintf(tw, "\n")

	diag, err := getDiagnostics(context.Background())
	if err != nil {
		return fmt.Errorf("could not get debug (diagnostics) info: %w", err)
	}

	sprintCMD, err := getFormatStr(formatRemote, formatLocal, c.Flags())
	if err != nil {
		return fmt.Errorf("debug command failed: %w", err)
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

func getFormatStr(fmtRemote, fmtLocal string, flags *pflag.FlagSet) (func(name string, pid int64) string, error) {
	local, err := flags.GetBool(flagLocal)
	if err != nil {
		return nil, fmt.Errorf("could not get flag %q error: %v", flagLocal, err)
	}
	if local {
		return func(name string, pid int64) string {
			return fmt.Sprintf(fmtLocal, name, pid)
		}, nil
	}

	port, err := flags.GetString(flagPort)
	if err != nil {
		return nil, fmt.Errorf("could not get flag %q error: %v", flagPort, err)
	}
	return func(name string, pid int64) string {
		return fmt.Sprintf(fmtRemote, name, port, pid)
	}, nil
}

func getFormatCmdStr(fmtRemote, fmtLocal string, flags *pflag.FlagSet) (func(pid int64) string, error) {
	local, err := flags.GetBool(flagLocal)
	if err != nil {
		return nil, fmt.Errorf("could not get flag %q error: %v", flagLocal, err)
	}
	if local {
		return func(pid int64) string {
			return fmt.Sprintf(fmtLocal, pid)
		}, nil
	}

	port, err := flags.GetString(flagPort)
	if err != nil {
		return nil, fmt.Errorf("could not get flag %q error: %v", flagPort, err)
	}
	return func(pid int64) string {
		return fmt.Sprintf(fmtRemote, port, pid)
	}, nil
}

func newDebugRunCommand(streams *cli.IOStreams, getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [application]",
		Short: "runs Delve for an application.",
		Long:  "runs Delve for an application.",
		RunE: func(c *cobra.Command, args []string) error {
			err := debugRunCmd(streams, c, args, getDiagnostics)
			if err != nil {
				return err
			}
			return nil
		},
	}

	return cmd
}

func debugRunCmd(s *cli.IOStreams, c *cobra.Command, args []string, getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)) error {
	fmt.Fprintf(s.Out, "inside run cmg\n\n")
	diag, err := getDiagnostics(context.Background())
	if err != nil {
		return fmt.Errorf("could not get debug (diagnostics) info: %w", err)
	}

	sprintCMD, err := getFormatCmdStr(cmdRemote, cmdLocal, c.Flags())
	if err != nil {
		return fmt.Errorf("debug command failed: %w", err)
	}

	pdiag := parseDiagnostics(diag)

	for _, app := range pdiag {
		for _, arg := range args {
			if app.name == arg {
				fmt.Fprintf(s.Out, sprintCMD(app.pid))
				return nil
			}
		}
	}

	fmt.Fprintf(s.Out, "choose an application!\n")
	return nil
}

func parseDiagnostics(d DiagnosticsInfo) []debugData {
	parsed := []debugData{{
		name: "elastic-agent",
		pid:  d.AgentInfo.PID,
	}}

	for _, p := range d.ProcMetas {
		parsed = append(parsed, debugData{
			name: p.Name,
			pid:  p.PID,
		})
	}

	return parsed
}
