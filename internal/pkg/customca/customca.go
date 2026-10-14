// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package customca keeps the NSS database that Chromium reads in sync with the
// CA certificates mounted in a container, so browser monitors trust them.
//
// Chromium ignores the system trust store and only reads $HOME/.pki/nssdb.
package customca

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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultDir is where CAs are mounted: the standard location on Debian-based systems.
	DefaultDir = "/usr/local/share/ca-certificates"
	// DefaultInterval is how often the directory is checked for changes.
	DefaultInterval = 30 * time.Second

	// nicknamePrefix marks the certificates managed here, so others in the database are left alone.
	nicknamePrefix = "custom-ca-"
)

// Logger is the subset of a logger used here.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Runner runs certutil with the given arguments.
type Runner func(ctx context.Context, args ...string) ([]byte, error)

// ExecRunner returns a Runner that runs the certutil binary at path.
func ExecRunner(path string) Runner {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("certutil %s: %w: %s", args[0], err, bytes.TrimSpace(out))
		}
		return out, nil
	}
}

// Owner is the user and group that must own the database, so a browser running as
// another user can read it. It requires running as root.
type Owner struct {
	UID, GID int
}

// Config configures a Manager.
type Config struct {
	// Dir holds the PEM files (*.crt, *.pem) to trust.
	Dir string
	// Home is the browser's home directory; the database is <Home>/.pki/nssdb.
	Home string
	// Interval is how often Run checks Dir for changes.
	Interval time.Duration
	// Runner runs certutil.
	Runner Runner
	// Owner, if set, owns the database after each sync.
	Owner *Owner
	Log   Logger
}

// Manager imports the CAs in a directory into an NSS database and keeps it in sync.
type Manager struct {
	cfg Config

	mu sync.Mutex
	// applied is the digest of the files last synced successfully. A failed sync
	// leaves it unchanged, so the same change is retried.
	applied string
	synced  bool
}

// New returns a Manager for cfg.
func New(cfg Config) *Manager {
	if cfg.Dir == "" {
		cfg.Dir = DefaultDir
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	return &Manager{cfg: cfg}
}

func (m *Manager) dbDir() string {
	return filepath.Join(m.cfg.Home, ".pki", "nssdb")
}

// files returns the PEM files in the directory, sorted.
func (m *Manager) files() []string {
	var files []string
	for _, pattern := range []string{"*.crt", "*.pem"} {
		matches, _ := filepath.Glob(filepath.Join(m.cfg.Dir, pattern))
		files = append(files, matches...)
	}
	var regular []string
	for _, f := range files {
		// Stat follows symlinks, which is how Kubernetes mounts Secrets.
		if info, err := os.Stat(f); err == nil && info.Mode().IsRegular() {
			regular = append(regular, f)
		}
	}
	sort.Strings(regular)
	return regular
}

// HasWork reports whether there is anything to sync: CAs to import, or an
// existing database whose managed certificates may need removing.
func (m *Manager) HasWork() bool {
	if len(m.files()) > 0 {
		return true
	}
	_, err := os.Stat(filepath.Join(m.dbDir(), "cert9.db"))
	return err == nil
}

// digest hashes the content of the PEM files.
func (m *Manager) digest() (string, error) {
	h := sha256.New()
	for _, f := range m.files() {
		data, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		h.Write([]byte(filepath.Base(f)))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// certificates decodes the CAs in the directory, keyed by nickname. The nickname
// derives from the decoded certificate, so reformatting a PEM or listing a CA twice
// never renames or drops it.
func (m *Manager) certificates() (map[string][]byte, error) {
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
				m.warnf("ignoring an invalid certificate in %s: %v", filepath.Base(f), err)
				continue
			}
			sum := sha256.Sum256(block.Bytes)
			want[nicknamePrefix+hex.EncodeToString(sum[:8])] = block.Bytes
		}
	}
	return want, errors.Join(errs...)
}

// Sync makes the database hold exactly the certificates in the directory. It
// returns an error if anything could not be done; the change stays pending and
// Run retries it. Certificates already in the database are never touched, so
// running browsers see no gap.
func (m *Manager) Sync(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncLocked(ctx)
}

func (m *Manager) syncLocked(ctx context.Context) error {
	// Hash first: if the files change while syncing, the next check sees it.
	sum, err := m.digest()
	if err != nil {
		return fmt.Errorf("reading CA files: %w", err)
	}

	db := m.dbDir()
	dbArg := "sql:" + db
	if err := os.MkdirAll(db, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", db, err)
	}
	if _, err := os.Stat(filepath.Join(db, "cert9.db")); err != nil {
		if _, err := m.cfg.Runner(ctx, "-N", "-d", dbArg, "--empty-password"); err != nil {
			return fmt.Errorf("creating NSS database: %w", err)
		}
	}

	// Listing fails first on a corrupt database: stop before any change.
	out, err := m.cfg.Runner(ctx, "-L", "-d", dbArg)
	if err != nil {
		return fmt.Errorf("reading NSS database (corrupt?): %w", err)
	}
	existing := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasPrefix(fields[0], nicknamePrefix) {
			existing[fields[0]] = true
		}
	}

	want, errCerts := m.certificates()
	errs := []error{errCerts}

	tmp, err := os.MkdirTemp("", "customca-")
	if err != nil {
		return fmt.Errorf("creating a temporary directory: %w", err)
	}
	defer os.RemoveAll(tmp)

	var added, removed int
	for nick, der := range want {
		if existing[nick] {
			continue
		}
		file := filepath.Join(tmp, nick+".pem")
		if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := m.cfg.Runner(ctx, "-A", "-d", dbArg, "-n", nick, "-t", "C,,", "-i", file); err != nil {
			errs = append(errs, fmt.Errorf("importing %s: %w", nick, err))
			continue
		}
		added++
	}
	for nick := range existing {
		if _, ok := want[nick]; ok {
			continue
		}
		if _, err := m.cfg.Runner(ctx, "-D", "-d", dbArg, "-n", nick); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", nick, err))
			continue
		}
		removed++
	}

	// The browser may run as another user: it must be able to read the database.
	if m.cfg.Owner != nil {
		if err := chownTree(filepath.Join(m.cfg.Home, ".pki"), m.cfg.Owner); err != nil {
			errs = append(errs, fmt.Errorf("changing the database owner: %w", err))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}
	m.applied, m.synced = sum, true
	if added > 0 || removed > 0 {
		m.infof("Custom CA certificates in the browser trust store: %d (added %d, removed %d)", len(want), added, removed)
	}
	return nil
}

// Run checks the directory every Interval and syncs when its content changed or
// the last sync failed, until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		m.mu.Lock()
		sum, err := m.digest()
		unchanged := m.synced && sum == m.applied
		if err == nil && (unchanged || (!m.synced && !m.HasWork())) {
			m.mu.Unlock()
			continue
		}
		if err := m.syncLocked(ctx); err != nil {
			m.warnf("custom CA certificates not updated, will retry: %v", err)
		}
		m.mu.Unlock()
	}
}

func chownTree(dir string, o *Owner) error {
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
		return root.Lchown(path, o.UID, o.GID)
	})
}

func (m *Manager) infof(format string, args ...any) {
	if m.cfg.Log != nil {
		m.cfg.Log.Infof(format, args...)
	}
}

func (m *Manager) warnf(format string, args ...any) {
	if m.cfg.Log != nil {
		m.cfg.Log.Warnf(format, args...)
	}
}
