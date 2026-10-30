// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package customca

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// TestSyncWithRealCertutil runs the real certutil, which the fake can't vouch for.
// It is skipped where certutil isn't installed; the complete images have it.
func TestSyncWithRealCertutil(t *testing.T) {
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		t.Skip("certutil not installed")
	}
	dir := t.TempDir()
	home := t.TempDir()
	m := &manager{paths: []string{dir}, home: home, certs: execRunner(certutil), log: &testLog{}}
	list := func() string {
		out, err := m.certs(t.Context(), nil, "-L", "-d", "sql:"+filepath.Join(home, ".pki", "nssdb"))
		require.NoError(t, err, "listing the database")
		return string(out)
	}

	write(t, dir, "bundle.pem", newCA(t, "one")+newCA(t, "two"))
	require.NoError(t, m.reconcile(t.Context()), "importing a bundle through certutil's standard input")
	assert.Equal(t, 2, countManaged(list()), "both certificates of a bundle must be imported:\n%s", list())

	require.NoError(t, os.Remove(filepath.Join(dir, "bundle.pem")), "removing the bundle")
	require.NoError(t, m.reconcile(t.Context()), "removing the certificates")
	assert.Equal(t, 0, countManaged(list()), "removed certificates must leave the database:\n%s", list())
}

func countManaged(listing string) int {
	n := 0
	for _, line := range splitLines(listing) {
		if len(line) >= len(nicknamePrefix) && line[:len(nicknamePrefix)] == nicknamePrefix {
			n++
		}
	}
	return n
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	return append(lines, s[start:])
}

// TestStartCleansUpCAsNoLongerConfigured restarts with no CA left, as after removing
// the last CA file or the whole agent.synthetics section: the CAs a previous run
// imported must not stay trusted.
func TestStartCleansUpCAsNoLongerConfigured(t *testing.T) {
	certutil, err := exec.LookPath("certutil")
	if err != nil || runtime.GOOS != "linux" {
		t.Skip("needs certutil on Linux")
	}
	for name, cfg := range map[string]func(dir string) Config{
		"empty directory": func(dir string) Config { return Config{CertificateAuthorities: []string{dir}} },
		"missing path": func(dir string) Config {
			return Config{CertificateAuthorities: []string{filepath.Join(dir, "missing")}}
		},
		"no configuration": func(string) Config { return Config{} },
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv(browserUserEnv, "")
			dir := t.TempDir()
			previous := &manager{paths: []string{dir}, home: home, certs: execRunner(certutil), log: &testLog{}}
			write(t, dir, "ca.pem", newCA(t, "previous run"))
			require.NoError(t, previous.reconcile(t.Context()), "importing a CA in a previous run")
			require.NoError(t, os.Remove(filepath.Join(dir, "ca.pem")), "removing the CA before the restart")

			log, _ := loggertest.New(t.Name())
			Start(t.Context(), log, cfg(dir))

			out, err := previous.certs(t.Context(), nil, "-L", "-d", "sql:"+filepath.Join(home, ".pki", "nssdb"))
			require.NoError(t, err, "listing the database")
			assert.Zero(t, countManaged(string(out)), "a CA no longer configured must be removed at start:\n%s", out)
		})
	}
}
