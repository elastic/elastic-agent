// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package customca

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
