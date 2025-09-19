package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/spf13/cobra"
)

func newOtelDiagnosticsCommand(streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Start the Elastic Agent in otel mode",
		Long:  "This command starts the Elastic Agent in otel mode.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := otelDiagnosticCmd(streams, cmd); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringP("file", "f", "", "name of the output diagnostics zip archive")
	return cmd
}

func otelDiagnosticCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	daemon := client.New(client.WithAddress(control.AdressEDOT()))
	if err := daemon.Connect(cmd.Context()); err != nil {
		return err
	}
	agentDiag, err := daemon.DiagnosticAgent(cmd.Context(), nil)
	if err != nil {
		return fmt.Errorf("failed to get edot agent diagnostics: %v", err)
	}

	componentDiag, err := daemon.DiagnosticComponents(cmd.Context(), nil)
	if err != nil {
		return fmt.Errorf("failed to get edot componen diagnostics: %v", err)
	}
	filepath, _ := cmd.Flags().GetString("file")
	if filepath == "" {
		ts := time.Now().UTC()
		filepath = "edot-diagnostics-" + ts.Format("2006-01-02T15-04-05Z07-00") + ".zip" // RFC3339 format that replaces : with -, so it will work on Windows
	}
	f, err := createFile(filepath)
	if err != nil {
		return fmt.Errorf("could not create diagnostics file %q: %w", filepath, err)
	}
	defer f.Close()

	return diagnostics.ZipArchiveEDOT(streams.Err, f, paths.Top(), agentDiag, componentDiag)
}
