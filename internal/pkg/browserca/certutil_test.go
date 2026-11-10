// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package browserca

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

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
	m := &manager{paths: []string{dir}, home: home, certs: execRunner(certutil, nil), log: &testLog{}}
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
			previous := &manager{paths: []string{dir}, home: home, certs: execRunner(certutil, nil), log: &testLog{}}
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

// Configured paths may be populated after the agent starts, for example by a
// sidecar provisioning the CA. Watch them even when no database exists yet.
func TestStartWatchesInitiallyMissingPaths(t *testing.T) {
	certutil, err := exec.LookPath("certutil")
	if err != nil || runtime.GOOS != "linux" {
		t.Skip("needs certutil on Linux")
	}
	for _, name := range []string{"file", "directory", "dangling symlink", "reload disabled"} {
		t.Run(name, func(t *testing.T) {
			home, dir := t.TempDir(), t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv(browserUserEnv, "")
			caPath := filepath.Join(dir, "ca.pem")
			configuredPath := caPath
			switch name {
			case "directory":
				configuredPath = filepath.Join(dir, "late")
				caPath = filepath.Join(configuredPath, "ca.pem")
			case "dangling symlink":
				configuredPath = filepath.Join(dir, "link.pem")
				require.NoError(t, os.Symlink(caPath, configuredPath))
			}
			cfg := Config{CertificateAuthorities: []string{configuredPath}}
			// Exercise the minimum interval through Start, including the disabled case.
			cfg.CertificateReload.ReloadInterval = time.Nanosecond
			if name == "reload disabled" {
				disabled := false
				cfg.CertificateReload.Enabled = &disabled
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			log, logs := loggertest.New(t.Name())
			Start(ctx, log, cfg)
			assert.Equal(t, name != "reload disabled", logs.FilterMessageSnippet("below the minimum of 1s").Len() == 1)
			require.NoDirExists(t, filepath.Join(home, ".pki"), "do not create a store before a CA exists")

			require.NoError(t, os.MkdirAll(filepath.Dir(caPath), 0o700))
			require.NoError(t, os.WriteFile(caPath, []byte(newCA(t, "late CA")), 0o600))
			if name == "reload disabled" {
				assert.Never(t, func() bool {
					return exists(filepath.Join(home, ".pki"))
				}, 1250*time.Millisecond, testInterval, "disabled reload must not import a late CA")
				return
			}
			require.Eventually(t, func() bool {
				out, err := execRunner(certutil, nil)(ctx, nil, "-L", "-d", "sql:"+filepath.Join(home, ".pki", "nssdb"))
				return err == nil && countManaged(string(out)) == 1
			}, 5*time.Second, testInterval, "a CA appearing after startup must be imported without restarting")
		})
	}
}

// rootTestHome returns a home directory the user o can use, as a root agent's browser
// user would have.
func rootTestHome(t *testing.T, o *owner) string {
	t.Helper()
	home, err := os.MkdirTemp("", "browserca-home-")
	require.NoError(t, err, "creating the browser home")
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	require.NoError(t, os.Chmod(home, 0o755), "making the home traversable")
	require.NoError(t, os.Chown(home, int(o.uid), int(o.gid)), "giving the home to the browser user")
	return home
}

func rootTestOwner(t *testing.T) (string, *owner) {
	t.Helper()
	certutil, err := exec.LookPath("certutil")
	if err != nil || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs certutil on Linux, as root")
	}
	_, o, err := lookupBrowserUser("nobody")
	require.NoError(t, err, "looking up nobody")
	return certutil, o
}

// TestSyncAsRootRunsCertutilAsTheBrowserUser checks that, as root, the database is
// created by and belongs to the browser user.
func TestSyncAsRootRunsCertutilAsTheBrowserUser(t *testing.T) {
	certutil, o := rootTestOwner(t)
	home := rootTestHome(t, o)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755), "making the CA directory readable")
	write(t, dir, "ca.pem", newCA(t, "ca"))
	m := &manager{paths: []string{dir}, home: home, certs: execRunner(certutil, o), owner: o, log: &testLog{}}

	require.NoError(t, m.reconcile(t.Context()), "importing as the browser user")

	for _, name := range []string{".pki", ".pki/nssdb", ".pki/nssdb/cert9.db"} {
		info, err := os.Stat(filepath.Join(home, name))
		require.NoError(t, err, "stat %s", name)
		assert.Equal(t, o.uid, info.Sys().(*syscall.Stat_t).Uid, "%s must belong to the browser user", name)
	}
}

// TestSyncAsRootDoesNotFollowASymlinkedDatabase plants the database directory as a
// symlink to a directory only root can write, as a browser user could: the sync must
// fail without writing there.
func TestSyncAsRootDoesNotFollowASymlinkedDatabase(t *testing.T) {
	certutil, o := rootTestOwner(t)
	home := rootTestHome(t, o)
	target := t.TempDir() // root's, 0700
	require.NoError(t, os.Mkdir(filepath.Join(home, ".pki"), 0o700), "creating .pki")
	require.NoError(t, os.Chown(filepath.Join(home, ".pki"), int(o.uid), int(o.gid)), "giving .pki to the browser user")
	require.NoError(t, os.Symlink(target, filepath.Join(home, ".pki", "nssdb")), "planting the symlink")
	dir := t.TempDir()
	write(t, dir, "ca.pem", newCA(t, "ca"))
	m := &manager{paths: []string{dir}, home: home, certs: execRunner(certutil, o), owner: o, log: &testLog{}}

	require.Error(t, m.reconcile(t.Context()), "a symlinked database directory must fail the sync")

	entries, err := os.ReadDir(target)
	require.NoError(t, err, "listing the symlink target")
	assert.Empty(t, entries, "nothing may be written where the symlink points")
	info, err := os.Stat(target)
	require.NoError(t, err, "stat the symlink target")
	assert.Zero(t, info.Sys().(*syscall.Stat_t).Uid, "the symlink target must still belong to root")
}

func TestRootOwnershipRepairLeavesUnrelatedFilesAlone(t *testing.T) {
	certutil, o := rootTestOwner(t)
	home := rootTestHome(t, o)
	m := &manager{home: home, certs: execRunner(certutil, nil), log: &testLog{}}
	// Simulate a database created by root before ownership repair.
	require.NoError(t, os.MkdirAll(m.dbDir(), 0o700))
	_, err := m.certs(t.Context(), nil, "-N", "-d", "sql:"+m.dbDir(), "--empty-password")
	require.NoError(t, err)
	unrelated := []string{filepath.Join(home, ".pki", "other.pem"), filepath.Join(m.dbDir(), "other.db")}
	for _, path := range unrelated {
		require.NoError(t, os.WriteFile(path, []byte("untouched"), 0o600))
	}
	m.owner, m.certs = o, execRunner(certutil, o)
	m.paths = []string{t.TempDir()}
	write(t, m.paths[0], "ca.pem", newCA(t, "ca"))
	require.NoError(t, m.reconcile(t.Context()))
	for _, path := range unrelated {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Zero(t, info.Sys().(*syscall.Stat_t).Uid)
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "untouched", string(content))
	}
	for _, name := range []string{"cert9.db", "key4.db", "pkcs11.txt"} {
		info, err := os.Stat(filepath.Join(m.dbDir(), name))
		require.NoError(t, err)
		assert.Equal(t, o.uid, info.Sys().(*syscall.Stat_t).Uid)
	}
}

func TestRootOwnershipRepairRejectsLinkedDatabaseFile(t *testing.T) {
	_, o := rootTestOwner(t)
	for _, link := range []string{"symlink", "hardlink"} {
		t.Run(link, func(t *testing.T) {
			m := &manager{home: rootTestHome(t, o), owner: o}
			require.NoError(t, os.MkdirAll(m.dbDir(), 0o700))
			target := filepath.Join(t.TempDir(), "target")
			require.NoError(t, os.WriteFile(target, []byte("untouched"), 0o600))
			path := filepath.Join(m.dbDir(), "cert9.db")
			if link == "symlink" {
				require.NoError(t, os.Symlink(target, path))
			} else {
				require.NoError(t, os.Link(target, path))
			}
			require.Error(t, m.prepareDBDir())
			info, err := os.Stat(target)
			require.NoError(t, err)
			assert.Zero(t, info.Sys().(*syscall.Stat_t).Uid)
		})
	}
}
