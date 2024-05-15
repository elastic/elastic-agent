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
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func DefaultTopPath() string {
	var defaultBasePath string
	switch runtime.GOOS {
	case "darwin":
		defaultBasePath = `/Library`
	case "linux":
		defaultBasePath = `/opt`
	case "windows":
		defaultBasePath = `C:\Program Files`
	}
	return filepath.Join(defaultBasePath, "Elastic", "Agent")
}

func CheckSuccess(f *atesting.Fixture, topPath string, unprivileged bool) error {
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

	// Check has agent ID and unprivileged mode matches.
	var output atesting.AgentStatusOutput
	err = waitForNoError(context.Background(), func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		output, err = f.ExecStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get the status: %w", err)
		}
		return nil
	}, 3*time.Minute, 10*time.Second)
	if output.Info.ID != "" {
		return fmt.Errorf("must have an agent ID")
	}
	if unprivileged != output.Info.Unprivileged {
		return fmt.Errorf("unprivileged didn't match, should have been %v", unprivileged)
	}

	// Specific checks depending on the platform.
	return checkPlatform(f, topPath, unprivileged)
}

func exeOnWindows(filename string) string {
	if runtime.GOOS == define.Windows {
		return filename + ".exe"
	}
	return filename
}

func waitForNoError(ctx context.Context, fun func(ctx context.Context) error, timeout time.Duration, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t := time.NewTicker(interval)
	defer t.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		case <-t.C:
			err := fun(ctx)
			if err == nil {
				return nil
			}
			lastErr = err
		}
	}
}
