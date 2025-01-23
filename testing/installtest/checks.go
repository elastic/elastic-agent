// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package installtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func defaultBasePath() string {
	var defaultBasePath string
	switch runtime.GOOS {
	case "darwin":
		defaultBasePath = `/Library`
	case "linux":
		defaultBasePath = `/opt`
	case "windows":
		defaultBasePath = `C:\Program Files`
	}
	return defaultBasePath
}

func DefaultTopPath() string {
	return filepath.Join(defaultBasePath(), "Elastic", "Agent")
}

func NamespaceTopPath(namespace string) string {
	return filepath.Join(defaultBasePath(), "Elastic", paths.InstallDirNameForNamespace(namespace))
}

type CheckOpts struct {
	Privileged bool
	Namespace  string
	Username   string
	Group      string
}

func CheckSuccess(ctx context.Context, f *atesting.Fixture, topPath string, opts *CheckOpts) error {
	// Use default topPath if one not defined.
	if topPath == "" {
		topPath = DefaultTopPath()
	}

	_, err := os.Stat(topPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", topPath, err)
	}

	// Check that a few expected installed files are present
	installedBinPath := filepath.Join(topPath, exeOnWindows("elastic-agent"))
	installedDataPath := filepath.Join(topPath, "data")
	installMarkerPath := filepath.Join(topPath, paths.MarkerFileName)

	_, err = os.Stat(installedBinPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", installedBinPath, err)
	}
	_, err = os.Stat(installedDataPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", installedDataPath, err)
	}
	_, err = os.Stat(installMarkerPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", installMarkerPath, err)
	}

	// Specific checks depending on the platform.
	return checkPlatform(ctx, f, topPath, opts)
}

func exeOnWindows(filename string) string {
	if runtime.GOOS == define.Windows {
		return filename + ".exe"
	}
	return filename
}
