// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
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
	logFilepath := path.Join(t.TempDir(), "flog.log")
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

	// logs of two previous builds
	previousBuilds := map[string]time.Duration{
		"1.0.0-aaaaaa": 2 * time.Hour,
		"1.0.1-bbbbbb": time.Hour,
	}
	for name, age := range previousBuilds {
		logFile := filepath.Join(logsRoot, name, "elastic-agent-20200101.ndjson")
		require.NoError(t, os.MkdirAll(filepath.Dir(logFile), 0o755))
		require.NoError(t, os.WriteFile(logFile, []byte("{}\n"), 0o600))
		ts := time.Now().Add(-age)
		require.NoError(t, os.Chtimes(logFile, ts, ts))
	}

	// the cleanup runs on every start: the first one removes the older previous build ...
	restartAndWait(ctx, t, fixture)
	assert.NoDirExists(t, filepath.Join(logsRoot, "1.0.0-aaaaaa"), "logs of the older previous build must be removed on startup")
	assert.DirExists(t, filepath.Join(logsRoot, "1.0.1-bbbbbb"), "logs of the latest previous build must be kept")
	assert.DirExists(t, filepath.Join(logsRoot, runningBuild), "logs of the running build must be kept")

	// ... and the next one keeps the remaining previous build, it is not removed because it is the oldest
	restartAndWait(ctx, t, fixture)
	assert.DirExists(t, filepath.Join(logsRoot, "1.0.1-bbbbbb"), "logs of the latest previous build must be kept on every startup")
	assert.DirExists(t, filepath.Join(logsRoot, runningBuild), "logs of the running build must be kept")
	assertNoLogsInInstallation(t, fixture.WorkDir())
}

// restartAndWait restarts the installed Agent and returns once the new process is running, which is after it
// has cleaned up the build logs: the restart command returns when the restart is triggered, not when it is done.
// The Agent restarts in place, so its process ID does not change. A start is seen in its log instead, and
// the control server of the new process answers only after its start up, which includes the cleanup.
func restartAndWait(ctx context.Context, t *testing.T, fixture *atesting.Fixture) {
	t.Helper()

	const startedMessage = "Elastic Agent started"
	starts := agentLogCount(t, fixture, startedMessage)

	restartOutput, err := fixture.Exec(ctx, []string{"restart"})
	require.NoErrorf(t, err, "restart failed: %s\noutput:\n%s", err, restartOutput)

	require.Eventually(t, func() bool {
		return agentLogCount(t, fixture, startedMessage) > starts
	}, 2*time.Minute, time.Second, "the Agent did not start again")
	require.Eventually(t, func() bool {
		_, err := fixture.ExecStatus(ctx, atesting.WithNoRetry())
		return err == nil
	}, 2*time.Minute, time.Second, "the Agent did not answer after the restart")
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
