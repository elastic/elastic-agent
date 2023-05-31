// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

var ErrNotInstalled = errors.New("Elastic Agent is not installed") //nolint:stylecheck // Elastic Agent is a proper noun

type CmdOpts interface {
	toCmdArgs() []string
}

type EnrollOpts struct {
	URL             string // --url
	EnrollmentToken string // --enrollment-token
}

func (e EnrollOpts) toCmdArgs() []string {
	var args []string
	if e.URL != "" {
		args = append(args, "--url", e.URL)
	}
	if e.EnrollmentToken != "" {
		args = append(args, "--enrollment-token", e.EnrollmentToken)
	}
	return args
}

type InstallOpts struct {
	BasePath       string // --base-path
	Force          bool   // --force
	NonInteractive bool   // --non-interactive

	EnrollOpts
}

func (i InstallOpts) toCmdArgs() []string {
	var args []string
	if i.BasePath != "" {
		args = append(args, "--base-path", i.BasePath)
	}
	if i.Force {
		args = append(args, "--force")
	}
	if i.NonInteractive {
		args = append(args, "--non-interactive")
	}

	args = append(args, i.EnrollOpts.toCmdArgs()...)

	return args
}

// Install installs the prepared Elastic Agent binary
func (f *Fixture) Install(ctx context.Context, installOpts *InstallOpts, opts ...process.CmdOption) ([]byte, error) {
	installArgs := []string{"install"}
	if installOpts != nil {
		installArgs = append(installArgs, installOpts.toCmdArgs()...)
	}
	out, err := f.Exec(ctx, installArgs, opts...)
	if err != nil {
		return nil, err
	}

	f.installed = true
	f.installOpts = installOpts

	if installOpts.BasePath == "" {
		f.workDir = filepath.Join(paths.DefaultBasePath, "Elastic", "Agent")
	} else {
		f.workDir = filepath.Join(installOpts.BasePath, "Elastic", "Agent")
	}

	//we just installed agent, the control socket is at a well-known location
	c := client.New(client.WithAddress(paths.ControlSocketPath))
	f.setClient(c)

	f.t.Cleanup(func() {
		out, err := f.Uninstall(ctx, &UninstallOpts{Force: true})
		f.setClient(nil)
		if errors.Is(err, ErrNotInstalled) {
			// Agent fixture has already been uninstalled, perhaps by
			// an explicit call to fixture.Uninstall, so nothing needs
			// to be done here.
			return
		}
		require.NoErrorf(f.t, err, "uninstalling agent failed. Output: %q", out)
	})

	return out, nil
}

type UninstallOpts struct {
	Force bool // --force
}

func (i UninstallOpts) toCmdArgs() []string {
	var args []string
	if i.Force {
		args = append(args, "--force")
	}

	return args
}

// Uninstall uninstalls the installed Elastic Agent binary
func (f *Fixture) Uninstall(ctx context.Context, uninstallOpts *UninstallOpts, opts ...process.CmdOption) ([]byte, error) {
	if !f.installed {
		return nil, ErrNotInstalled
	}

	uninstallArgs := []string{"uninstall"}
	if uninstallOpts != nil {
		uninstallArgs = append(uninstallArgs, uninstallOpts.toCmdArgs()...)
	}
	out, err := f.Exec(ctx, uninstallArgs, opts...)
	if err != nil {
		return out, err
	}

	// Check that Elastic Agent files are actually removed
	basePath := f.installOpts.BasePath
	if basePath == "" {
		basePath = paths.DefaultBasePath
	}
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	topPathStats, err := os.Stat(topPath)
	if errors.Is(err, fs.ErrNotExist) {
		// the path does not exist anymore, all good!
		return out, nil
	}

	if err != nil {
		return out, err
	}

	if err != nil && topPathStats != nil {
		return out, fmt.Errorf("Elastic Agent is still installed at [%s]", topPath) //nolint:stylecheck // Elastic Agent is a proper noun
	}

	return out, nil
}
