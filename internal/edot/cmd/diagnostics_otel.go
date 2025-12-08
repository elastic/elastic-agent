// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

func newOtelDiagnosticsCommand(streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Gather diagnostics information from the EDOT and write it to a zip archive",
		Long:  "This command gathers diagnostics information from the EDOT and writes it to a zip archive",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := otelDiagnosticCmd(streams, cmd); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage)
				os.Exit(1)
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringP("file", "f", "", "name of the output diagnostics zip archive")
	cmd.Flags().BoolP("cpu-profile", "p", false, "wait to collect a CPU profile")
	return cmd
}

func otelDiagnosticCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	cpuProfile, _ := cmd.Flags().GetBool("cpu-profile")
	resp, err := otel.PerformDiagnosticsExt(cmd.Context(), cpuProfile)
	if err != nil {
		return fmt.Errorf("failed to get edot diagnostics: %w", err)
	}

	agentDiag := make([]client.DiagnosticFileResult, 0)
	for _, r := range resp.GlobalDiagnostics {
		agentDiag = append(agentDiag, client.DiagnosticFileResult{
			Name:        r.Name,
			Filename:    r.Filename,
			ContentType: r.ContentType,
			Content:     r.Content,
			Description: r.Description,
		})
	}

	componentDiag := make([]client.DiagnosticComponentResult, 0)
	for _, r := range resp.ComponentDiagnostics {
		res := client.DiagnosticComponentResult{
			Results: make([]client.DiagnosticFileResult, 0),
		}
		res.Results = append(res.Results, client.DiagnosticFileResult{
			Name:        r.Name,
			Filename:    r.Filename,
			ContentType: r.ContentType,
			Content:     r.Content,
			Description: r.Description,
		})
		res.ComponentID = r.Name
		componentDiag = append(componentDiag, res)
	}
	componentDiag = aggregateComponentDiagnostics(componentDiag)

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

	// In EDOT, the logs path does not exist, so we ignore that error.
	if err := diagnostics.ZipArchive(streams.Err, f, paths.Top(), agentDiag, nil, componentDiag, false); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to create archive %q: %w", filepath, err)
	}
	fmt.Fprintf(streams.Out, "Created diagnostics archive %q\n", filepath)
	fmt.Fprintln(streams.Out, "** WARNING **\nCreated archive may contain plain text credentials.\nEnsure that files in archive are redacted before sharing.\n*******")
	return nil
}

// aggregateComponentDiagnostics takes a slice of DiagnosticComponentResult and merges
// results for components with the same ComponentID.
func aggregateComponentDiagnostics(diags []client.DiagnosticComponentResult) []client.DiagnosticComponentResult {
	m := make(map[string]client.DiagnosticComponentResult)
	for _, d := range diags {
		if existing, ok := m[d.ComponentID]; ok {
			existing.Results = append(existing.Results, d.Results...)
			m[d.ComponentID] = existing
		} else {
			m[d.ComponentID] = d
		}
	}
	result := make([]client.DiagnosticComponentResult, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}

func createFile(filepath string) (*os.File, error) {
	// Ensure all the folders on filepath exist as os.Create does not do so.
	// 0777 is the same permission, before unmask, os.Create uses.
	dir := path.Dir(filepath)
	if err := os.MkdirAll(dir, 0777); err != nil {
		return nil, fmt.Errorf("could not create folders to save diagnostics on %q: %w",
			dir, err)
	}

	f, err := os.Create(filepath)
	if err != nil {
		return nil, fmt.Errorf("error creating .zip file: %w", err)
	}
	return f, nil
}
