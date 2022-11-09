// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"archive/zip"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/component"
)

func newDiagnosticsCommand(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Gather diagnostics information from the elastic-agent and write it to a zip archive.",
		Long:  "Gather diagnostics information from the elastic-agent and write it to a zip archive.",
		Run: func(c *cobra.Command, args []string) {
			if err := diagnosticCmd(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringP("file", "f", "", "name of the output diagnostics zip archive")

	return cmd
}

func diagnosticCmd(streams *cli.IOStreams, cmd *cobra.Command) error {
	fileName, _ := cmd.Flags().GetString("file")
	if fileName == "" {
		ts := time.Now().UTC()
		fileName = "elastic-agent-diagnostics-" + ts.Format("2006-01-02T15-04-05Z07-00") + ".zip" // RFC3339 format that replaces : with -, so it will work on Windows
	}

	err := tryContainerLoadPaths()
	if err != nil {
		return err
	}

	ctx := handleSignal(context.Background())

	daemon := client.New()
	err = daemon.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer daemon.Disconnect()

	agentDiag, err := daemon.DiagnosticAgent(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch agent diagnostics: %w", err)
	}

	unitDiags, err := daemon.DiagnosticUnits(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch component/unit diagnostics: %w", err)
	}

	err = createZip(fileName, agentDiag, unitDiags)
	if err != nil {
		return fmt.Errorf("unable to create archive %q: %w", fileName, err)
	}
	fmt.Fprintf(streams.Out, "Created diagnostics archive %q\n", fileName)
	fmt.Fprintln(streams.Out, "***** WARNING *****\nCreated archive may contain plain text credentials.\nEnsure that files in archive are redacted before sharing.\n*******************")
	return nil
}

// createZip creates a zip archive with the passed fileName.
//
// The passed DiagnosticsInfo and AgentConfig data is written in the specified output format.
// Any local log files are collected and copied into the archive.
func createZip(fileName string, agentDiag []client.DiagnosticFileResult, unitDiags []client.DiagnosticUnitResult) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)

	// write all Elastic Agent diagnostics at the top level
	for _, ad := range agentDiag {
		zf, err := zw.Create(ad.Filename)
		if err != nil {
			return closeHandlers(err, zw, f)
		}
		_, err = zf.Write(ad.Content)
		if err != nil {
			return closeHandlers(err, zw, f)
		}
	}

	// structure each unit into its own component directory
	compDirs := make(map[string][]client.DiagnosticUnitResult)
	for _, ud := range unitDiags {
		compDir := strings.ReplaceAll(ud.ComponentID, "/", "-")
		compDirs[compDir] = append(compDirs[compDir], ud)
	}

	// write each units diagnostics into its own directory
	// layout becomes components/<component-id>/<unit-id>/<filename>
	_, err = zw.Create("components/")
	if err != nil {
		return closeHandlers(err, zw, f)
	}
	for dirName, units := range compDirs {
		_, err = zw.Create(fmt.Sprintf("components/%s/", dirName))
		if err != nil {
			return closeHandlers(err, zw, f)
		}
		for _, ud := range units {
			unitDir := strings.ReplaceAll(strings.TrimPrefix(ud.UnitID, ud.ComponentID+"-"), "/", "-")
			_, err = zw.Create(fmt.Sprintf("components/%s/%s/", dirName, unitDir))
			if err != nil {
				return closeHandlers(err, zw, f)
			}
			if ud.Err != nil {
				w, err := zw.Create(fmt.Sprintf("components/%s/%s/error.txt", dirName, unitDir))
				if err != nil {
					return closeHandlers(err, zw, f)
				}
				_, err = w.Write([]byte(fmt.Sprintf("%s\n", ud.Err)))
				if err != nil {
					return closeHandlers(err, zw, f)
				}
				continue
			}
			for _, fr := range ud.Results {
				w, err := zw.Create(fmt.Sprintf("components/%s/%s/%s", dirName, unitDir, fr.Name))
				if err != nil {
					return closeHandlers(err, zw, f)
				}
				_, err = w.Write(fr.Content)
				if err != nil {
					return closeHandlers(err, zw, f)
				}
			}
		}
	}

	if err := zipLogs(zw); err != nil {
		return closeHandlers(err, zw, f)
	}

	return closeHandlers(nil, zw, f)
}

// zipLogs walks paths.Logs() and copies the file structure into zw in "logs/"
func zipLogs(zw *zip.Writer) error {
	_, err := zw.Create("logs/")
	if err != nil {
		return err
	}

	if err := collectServiceComponentsLogs(zw); err != nil {
		return fmt.Errorf("failed to collect endpoint-security logs: %w", err)
	}

	// using Data() + "/logs", for some reason default paths/Logs() is the home dir...
	logPath := filepath.Join(paths.Home(), "logs") + string(filepath.Separator)
	return filepath.WalkDir(logPath, func(path string, d fs.DirEntry, fErr error) error {
		if stderrors.Is(fErr, fs.ErrNotExist) {
			return nil
		}
		if fErr != nil {
			return fmt.Errorf("unable to walk log dir: %w", fErr)
		}

		// name is the relative dir/file name replacing any filepath seperators with /
		// this will clean log names on windows machines and will nop on *nix
		name := filepath.ToSlash(strings.TrimPrefix(path, logPath))
		if name == "" {
			return nil
		}

		if d.IsDir() {
			_, err := zw.Create("logs/" + name + "/")
			if err != nil {
				return fmt.Errorf("unable to create log directory in archive: %w", err)
			}
			return nil
		}

		return saveLogs(name, path, zw)
	})
}

func collectServiceComponentsLogs(zw *zip.Writer) error {
	platform, err := component.LoadPlatformDetail()
	if err != nil {
		return fmt.Errorf("failed to gather system information: %w", err)
	}
	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}
	for _, spec := range specs.ServiceSpecs() {
		if spec.Spec.Service.Log == nil || spec.Spec.Service.Log.Path == "" {
			// no log path set in specification
			continue
		}

		logPath := filepath.Dir(spec.Spec.Service.Log.Path) + string(filepath.Separator)
		err = filepath.WalkDir(logPath, func(path string, d fs.DirEntry, fErr error) error {
			if fErr != nil {
				if stderrors.Is(fErr, fs.ErrNotExist) {
					return nil
				}

				return fmt.Errorf("unable to walk log directory %q for service input %s: %w", logPath, spec.InputType, fErr)
			}

			name := filepath.ToSlash(strings.TrimPrefix(path, logPath))
			if name == "" {
				return nil
			}

			if d.IsDir() {
				return nil
			}

			return saveLogs("services/"+name, path, zw)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func saveLogs(name string, logPath string, zw *zip.Writer) error {
	lf, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("unable to open log file: %w", err)
	}
	zf, err := zw.Create("logs/" + name)
	if err != nil {
		return closeHandlers(fmt.Errorf("unable to create log file in archive: %w", err), lf)
	}
	_, err = io.Copy(zf, lf)
	if err != nil {
		return closeHandlers(fmt.Errorf("log file copy failed: %w", err), lf)
	}

	return lf.Close()
}

// closeHandlers will close all passed closers attaching any errors to the passed err and returning the result
func closeHandlers(err error, closers ...io.Closer) error {
	var mErr *multierror.Error
	mErr = multierror.Append(mErr, err)
	for _, c := range closers {
		if inErr := c.Close(); inErr != nil {
			mErr = multierror.Append(mErr, inErr)
		}
	}
	return mErr.ErrorOrNil()
}
