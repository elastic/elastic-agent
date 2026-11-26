// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package pathstest changes the global agent paths for the duration of a test.
//
// The paths are process-wide, so a test that changes them without restoring them
// breaks the tests that run after it. These helpers restore the previous value
// when the test ends.
package pathstest

import (
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// SetTop sets the top path until the end of the test.
func SetTop(t testing.TB, path string) {
	t.Helper()
	orig := paths.Top()
	t.Cleanup(func() { paths.SetTop(orig) })
	paths.SetTop(path)
}

// SetInstallNamespace sets the installation namespace until the end of the test.
func SetInstallNamespace(t testing.TB, namespace string) {
	t.Helper()
	orig := paths.InstallNamespace()
	t.Cleanup(func() { paths.SetInstallNamespace(orig) })
	paths.SetInstallNamespace(namespace)
}

// SetConfig sets the config path until the end of the test.
func SetConfig(t testing.TB, path string) {
	t.Helper()
	orig := paths.Config()
	t.Cleanup(func() { paths.SetConfig(orig) })
	paths.SetConfig(path)
}

// SetLogs sets the logs path until the end of the test.
func SetLogs(t testing.TB, path string) {
	t.Helper()
	orig := paths.Logs()
	t.Cleanup(func() { paths.SetLogs(orig) })
	paths.SetLogs(path)
}

// SetDownloads sets the downloads path until the end of the test.
func SetDownloads(t testing.TB, path string) {
	t.Helper()
	orig := paths.Downloads()
	t.Cleanup(func() { paths.SetDownloads(orig) })
	paths.SetDownloads(path)
}

// SetVersionHome sets whether the home path is versioned until the end of the test.
func SetVersionHome(t testing.TB, version bool) {
	t.Helper()
	orig := paths.IsVersionHome()
	t.Cleanup(func() { paths.SetVersionHome(orig) })
	paths.SetVersionHome(version)
}

// SetDiagnosticsExtensionSocket sets the diagnostics extension socket path until the end of the test.
func SetDiagnosticsExtensionSocket(t testing.TB, path string) {
	t.Helper()
	orig := paths.DiagnosticsExtensionSocket()
	t.Cleanup(func() { paths.SetDiagnosticsExtensionSocket(orig) })
	paths.SetDiagnosticsExtensionSocket(path)
}
