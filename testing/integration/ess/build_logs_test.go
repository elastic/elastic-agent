// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/pkg/logp"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

// TestBuildLogsCleanupOnStartup verifies that an installed Agent keeps, next to the logs of the running
// build, only the logs of the most recently written previous build and removes the rest on startup.
func TestBuildLogsCleanupOnStartup(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		// `elastic-agent install` requires sudo
		Sudo: true,
		// installs Elastic Agent, not safe to run locally
		Local: false,
	})

	ctx, cancel := testcontext.WithTimeout(t, t.Context(), 10*time.Minute)
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	esURL := integration.StartMockES(t, 0, 0, 0, 0)
	logFilepath := filepath.Join(t.TempDir(), "flog.log")
	integration.GenerateLogFile(t, logFilepath, time.Millisecond*500, 0)
	cfg := fmt.Sprintf(eventLogConfig, esURL.String(), logFilepath, logp.InfoLevel.String(), runtimeProcess)

	require.NoError(t, fixture.Prepare(ctx))
	require.NoError(t, fixture.Configure(ctx, []byte(cfg)))

	output, err := fixture.InstallWithoutEnroll(ctx, &atesting.InstallOpts{
		NonInteractive: true,
		Privileged:     true,
		Force:          true,
	})
	require.NoErrorf(t, err, "install failed: %s\noutput:\n%s", err, output)

	logsRoot := filepath.Join(fixture.WorkDir(), "data", "logs")
	runningBuildLogs := func() []string {
		entries, err := os.ReadDir(logsRoot)
		if err != nil {
			return nil
		}
		var dirs []string
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, e.Name())
			}
		}
		return dirs
	}
	require.Eventually(t, func() bool { return len(runningBuildLogs()) == 1 }, time.Minute, time.Second,
		"the running build must have exactly one log directory under %s", logsRoot)
	runningBuild := runningBuildLogs()[0]
	seed := func(builds map[string]time.Duration) {
		for name, age := range builds {
			logFile := filepath.Join(logsRoot, name, "elastic-agent-20200101.ndjson")
			require.NoError(t, os.MkdirAll(filepath.Dir(logFile), 0o755))
			require.NoError(t, os.WriteFile(logFile, []byte("{}\n"), 0o600))
			ts := time.Now().Add(-age)
			require.NoError(t, os.Chtimes(logFile, ts, ts))
		}
	}
	removed := func(names ...string) bool {
		for _, name := range names {
			if _, err := os.Stat(filepath.Join(logsRoot, name)); !os.IsNotExist(err) {
				return false
			}
		}
		return true
	}

	// logs of three previous builds: only the one written last is kept, whatever the names are, and not just the
	// oldest one is removed
	seed(map[string]time.Duration{
		"1.0.0-aaaaaa": time.Hour,
		"1.0.1-bbbbbb": 2 * time.Hour,
		"1.0.2-cccccc": 3 * time.Hour,
	})
	triggerRestart(ctx, t, fixture)
	// the cleanup runs next to the Agent, so wait for its effect
	require.Eventually(t, func() bool { return removed("1.0.1-bbbbbb", "1.0.2-cccccc") }, 2*time.Minute, time.Second,
		"logs of the older previous builds must be removed on startup")
	assert.DirExists(t, filepath.Join(logsRoot, "1.0.0-aaaaaa"), "logs of the latest previous build must be kept")
	assert.DirExists(t, filepath.Join(logsRoot, runningBuild), "logs of the running build must be kept")

	// the cleanup runs on every start: an older build with a greater name is removed, the latest one is still kept
	seed(map[string]time.Duration{"2.0.0-dddddd": 4 * time.Hour})
	triggerRestart(ctx, t, fixture)
	require.Eventually(t, func() bool { return removed("2.0.0-dddddd") }, 2*time.Minute, time.Second,
		"logs of an older previous build must be removed on every startup")
	assert.DirExists(t, filepath.Join(logsRoot, "1.0.0-aaaaaa"), "logs of the latest previous build must be kept on every startup")
	assert.DirExists(t, filepath.Join(logsRoot, runningBuild), "logs of the running build must be kept")
	assertNoLogsInInstallation(t, fixture.WorkDir())
}

// triggerRestart restarts the installed Agent. The restart command returns when the restart is triggered, not when
// it is done.
func triggerRestart(ctx context.Context, t *testing.T, fixture *atesting.Fixture) {
	t.Helper()

	restartOutput, err := fixture.Exec(ctx, []string{"restart"})
	require.NoErrorf(t, err, "restart failed: %s\noutput:\n%s", err, restartOutput)
}

// assertNoLogsInInstallation fails if the installation directories of the Agent installed in topPath have log files.
// The logs of the Agent and of its components are written to data/logs/<build>, so anything that is created in
// the logs directories of the installation, for example by a component that does not use the logs path it is given,
// is reported.
func assertNoLogsInInstallation(t *testing.T, topPath string) {
	t.Helper()

	for _, installationLogsDir := range []string{
		filepath.Join(topPath, "data", "elastic-agent-*", "logs"),
		filepath.Join(topPath, "data", "elastic-agent-*", "components", "logs"),
	} {
		assertNoFilesIn(t, installationLogsDir)
	}
}

// assertNoFilesIn fails if any file exists below a directory matching dirGlob.
func assertNoFilesIn(t *testing.T, dirGlob string) {
	t.Helper()

	dirs, err := filepath.Glob(dirGlob)
	require.NoError(t, err)
	for _, dir := range dirs {
		assert.NoError(t, upgradetest.CheckNoFilesIn(dir))
	}
}

// requireBuildLogs waits until the Agent installed in workDir has a non-empty Agent log file in the log directory
// of the build, see upgradetest.BuildLogsDirName. It does not match by commit alone: builds made from the same
// binary share the commit, and the directory of the running build must not stand in for another one.
func requireBuildLogs(t *testing.T, workDir, buildLogsDirName string) {
	t.Helper()

	requireLogFileInDir(t, filepath.Join(workDir, "data", "logs", buildLogsDirName, "elastic-agent-*.ndjson"), "build logs")
}

// requireDiagnosticsBuildLogs collects the diagnostics of the installed fixture and checks that the bundle has
// the watcher log of the build with the given log directory name.
func requireDiagnosticsBuildLogs(ctx context.Context, t *testing.T, fixture *atesting.Fixture, buildLogsDirName string) {
	t.Helper()

	archive, err := fixture.ExecDiagnostics(ctx, "diagnostics", "collect")
	require.NoError(t, err, "error collecting diagnostics")

	dir := t.TempDir()
	extractZipArchive(t, archive, dir)

	pattern := filepath.Join(dir, "logs", "elastic-agent-"+buildLogsDirName, "elastic-agent-watcher-*.ndjson")
	files, err := filepath.Glob(pattern)
	require.NoError(t, err)
	assert.NotEmpty(t, files, "the diagnostics bundle must have the watcher log of the build, matching %s", pattern)
}
