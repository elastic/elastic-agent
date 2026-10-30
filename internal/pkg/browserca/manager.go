// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package browserca keeps the NSS database that Chromium reads in sync with the
// CA certificates configured under agent.synthetics.browser, so browser monitors
// trust them.
//
// Chromium ignores the system trust store on Linux and only reads $HOME/.pki/nssdb.
package browserca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	// defaultInterval is how often the CAs are checked for changes when
	// certificate_reload.reload_interval is not set.
	defaultInterval = 30 * time.Second

	// nicknamePrefix marks the certificates managed here, so others in the database are left alone.
	nicknamePrefix = "custom-ca-"
)

// logs is the subset of a logger used here.
type logs interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// runner runs certutil with the given standard input and arguments.
type runner func(ctx context.Context, stdin []byte, args ...string) ([]byte, error)

func execRunner(path string) runner {
	return func(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Stdin = bytes.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("certutil %s: %w: %s", args[0], err, bytes.TrimSpace(out))
		}
		return out, nil
	}
}

// owner is the user and group that must own the database, so a browser running as
// another user can read it. Changing it requires running as root.
type owner struct {
	uid, gid int
}

// manager imports the CAs found in a set of paths into an NSS database and keeps it in sync.
type manager struct {
	// paths are PEM files, or directories whose *.crt and *.pem files are read.
	paths []string
	// home is the browser's home directory; the database is <home>/.pki/nssdb.
	home  string
	certs runner
	owner *owner // if set, owns the database after each sync
	log   logs

	// applied holds the certificates of the last successful sync, nil until one
	// succeeds. A failed sync leaves it unchanged, so the change is retried.
	applied map[string][]byte
}

func (m *manager) dbDir() string {
	return filepath.Join(m.home, ".pki", "nssdb")
}

// files returns the PEM files in the configured paths, sorted and without duplicates.
func (m *manager) files() []string {
	var files []string
	for _, p := range m.paths {
		// Stat follows symlinks, which is how Kubernetes mounts Secrets.
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		for _, pattern := range []string{"*.crt", "*.pem"} {
			matches, _ := filepath.Glob(filepath.Join(p, pattern))
			files = append(files, matches...)
		}
	}
	files = slices.DeleteFunc(files, func(f string) bool {
		info, err := os.Stat(f)
		return err != nil || !info.Mode().IsRegular()
	})
	slices.Sort(files)
	return slices.Compact(files)
}

// certificates decodes the configured CAs, keyed by nickname. The nickname derives
// from the decoded certificate, so reformatting a PEM or listing a CA twice never
// renames or drops it.
func (m *manager) certificates() (map[string][]byte, error) {
	want := map[string][]byte{}
	var errs []error
	for _, f := range m.files() {
		data, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for rest := data; len(rest) > 0; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				// Retrying can't fix it: skip it, don't fail the sync.
				m.log.Warnf("ignoring an invalid certificate in %s: %v", filepath.Base(f), err)
				continue
			}
			sum := sha256.Sum256(block.Bytes)
			want[nicknamePrefix+hex.EncodeToString(sum[:8])] = block.Bytes
		}
	}
	return want, errors.Join(errs...)
}

// reconcile makes the database hold exactly the configured certificates. It does
// nothing when they are the ones the last successful sync applied, or when there is
// neither a certificate to import nor a database to clean up: the configured paths
// may exist empty (e.g. an empty Secret), and the agent's home must then stay as is.
// On error the change stays pending and the next call retries it.
func (m *manager) reconcile(ctx context.Context) error {
	want, err := m.certificates()
	if err != nil {
		// Leave the database alone until every CA file can be read: syncing a partial
		// set would remove the unreadable files' CAs, and once they are readable again
		// nothing would differ from the last successful sync to bring them back.
		return fmt.Errorf("reading CA files: %w", err)
	}
	if m.applied != nil && maps.EqualFunc(want, m.applied, bytes.Equal) {
		return nil
	}
	if len(want) == 0 && !m.hasDB() {
		m.applied = want
		return nil
	}
	if err := m.sync(ctx, want); err != nil {
		return err
	}
	m.applied = want
	return nil
}

func (m *manager) hasDB() bool {
	return exists(filepath.Join(m.dbDir(), "cert9.db"))
}

// sync imports the certificates in want that the database lacks and removes the
// managed ones it no longer wants. Certificates already in the database are never
// touched, so running browsers see no gap.
func (m *manager) sync(ctx context.Context, want map[string][]byte) error {
	db := m.dbDir()
	dbArg := "sql:" + db
	if err := os.MkdirAll(db, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", db, err)
	}
	if _, err := os.Stat(filepath.Join(db, "cert9.db")); err != nil {
		if _, err := m.certs(ctx, nil, "-N", "-d", dbArg, "--empty-password"); err != nil {
			return fmt.Errorf("creating NSS database: %w", err)
		}
	}

	// Listing fails first on a corrupt database: stop before any change.
	out, err := m.certs(ctx, nil, "-L", "-d", dbArg)
	if err != nil {
		return fmt.Errorf("reading NSS database (corrupt?): %w", err)
	}
	existing := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasPrefix(fields[0], nicknamePrefix) {
			existing[fields[0]] = true
		}
	}

	var errs []error
	var added, removed int
	for nick, der := range want {
		if existing[nick] {
			continue
		}
		// Without -i, certutil reads the certificate from its standard input.
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if _, err := m.certs(ctx, ca, "-A", "-d", dbArg, "-n", nick, "-t", "C,,", "-a"); err != nil {
			errs = append(errs, fmt.Errorf("importing %s: %w", nick, err))
			continue
		}
		added++
	}
	for nick := range existing {
		if _, ok := want[nick]; ok {
			continue
		}
		if _, err := m.certs(ctx, nil, "-D", "-d", dbArg, "-n", nick); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", nick, err))
			continue
		}
		removed++
	}

	// The browser may run as another user: it must be able to read the database.
	if m.owner != nil {
		if err := chownTree(filepath.Join(m.home, ".pki"), m.owner); err != nil {
			errs = append(errs, fmt.Errorf("changing the database owner: %w", err))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}
	if added > 0 || removed > 0 {
		m.log.Infof("Custom CA certificates in the browser trust store: %d (added %d, removed %d)", len(want), added, removed)
	}
	return nil
}

// run reconciles every interval until ctx is done.
func (m *manager) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := m.reconcile(ctx); err != nil {
			m.log.Warnf("custom CA certificates not updated, will retry: %v", err)
		}
	}
}

func chownTree(dir string, o *owner) error {
	// Walk through a Root so symlinks can't lead the chown outside of dir.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return root.Lchown(path, o.uid, o.gid)
	})
}
