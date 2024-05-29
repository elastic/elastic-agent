// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package installtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

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

func DevelopTopPath() string {
	return filepath.Join(defaultBasePath(), "Elastic", "DevelopmentAgent")
}

type CheckOpts struct {
	Unprivileged bool
	Develop      bool
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
	installMarkerPath := filepath.Join(topPath, ".installed")

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
