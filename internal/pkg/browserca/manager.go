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
	"io"
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

	// Bound each command, reconciliation, and startup wait independently.
	commandTimeout      = 5 * time.Second
	reconcileTimeout    = 30 * time.Second
	maxCAFileBytes      = 4 << 20
	maxCATotalBytes     = 16 << 20
	maxCAFiles          = 1024
	maxDirectoryEntries = 4096
	maxCertificates     = 4096
	maxCommandOutput    = 4 << 20

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

// execRunner runs the certutil at path, as o when it is set, so that certutil only
// gets the access to the database that the browser has.
func execRunner(path string, o *owner) runner {
	return func(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, commandTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, args...)
		// Bound waiting for inherited pipes if a child outlives certutil.
		cmd.WaitDelay = time.Second
		cmd.Stdin = bytes.NewReader(stdin)
		if o != nil {
			runAs(cmd, o)
		}
		var output limitedOutput
		cmd.Stdout, cmd.Stderr = &output, &output
		err := cmd.Run()
		out := output.buffer.Bytes()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if output.overflow {
			err = errors.Join(err, fmt.Errorf("certutil output exceeds %d bytes", maxCommandOutput))
		}
		if err != nil {
			return out, fmt.Errorf("certutil %s: %w: %s", args[0], err, bytes.TrimSpace(out[:min(len(out), 4096)]))
		}
		return out, nil
	}
}

// limitedOutput drains command output without retaining an unbounded buffer.
// exec serializes writes when stdout and stderr share the same writer.
type limitedOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if available := maxCommandOutput - b.buffer.Len(); n > available {
		p = p[:available]
		b.overflow = true
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

// owner is the user and group the browser runs as when the agent runs as root. They
// own the database, and certutil runs as them.
type owner struct {
	uid, gid uint32
}

// manager imports the CAs found in a set of paths into an NSS database and keeps it in sync.
type manager struct {
	// paths are PEM files, or directories whose *.crt and *.pem files are read.
	paths []string
	// home is the browser's home directory; the database is <home>/.pki/nssdb.
	home    string
	certs   runner
	inspect runner // read-only listing for unconfigured cleanup, before ownership repair
	owner   *owner // if set, owns the database; certs runs as it too
	log     logs

	// applied holds the certificates of the last successful sync, nil until one
	// succeeds and after one fails, so that the next check reconciles again.
	applied map[string][]byte
}

func (m *manager) dbDir() string {
	return filepath.Join(m.home, ".pki", "nssdb")
}

// files returns the PEM files in the configured paths, sorted and without duplicates.
// A path that doesn't exist has no CA, but any other error is returned: a CA that is
// configured but can't be listed must not be removed.
func (m *manager) files(ctx context.Context) ([]string, error) {
	var files []string
	entriesLeft := maxDirectoryEntries
	if len(m.paths) > maxCAFiles {
		return nil, fmt.Errorf("more than %d configured CA paths", maxCAFiles)
	}
	for _, p := range m.paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Stat follows symlinks, which is how Kubernetes mounts Secrets.
		info, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("CA path %s is not a regular file", p)
			}
			files = append(files, p)
		} else {
			entries, err := readDirectory(p, entriesLeft)
			if err != nil {
				return nil, err
			}
			entriesLeft -= len(entries)
			for _, e := range entries {
				if ext := filepath.Ext(e.Name()); ext != ".crt" && ext != ".pem" {
					continue
				}
				f := filepath.Join(p, e.Name())
				info, err := os.Stat(f)
				switch {
				case errors.Is(err, fs.ErrNotExist):
					// A dangling symlink.
				case err != nil:
					return nil, err
				case info.Mode().IsRegular():
					files = append(files, f)
				case !info.IsDir():
					return nil, fmt.Errorf("CA path %s is not a regular file", f)
				}
			}
		}
		if len(files) > maxCAFiles {
			return nil, fmt.Errorf("more than %d CA files", maxCAFiles)
		}
	}
	slices.Sort(files)
	return slices.Compact(files), nil
}

// readDirectory bounds allocation even for directories full of unrelated files.
func readDirectory(path string, limit int) ([]os.DirEntry, error) {
	// A directory discovered earlier can also be replaced by a FIFO.
	f, err := openCAFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, fmt.Errorf("CA directories contain more than %d entries", maxDirectoryEntries)
	}
	return entries, nil
}

func readCAFile(path string, limit int64) ([]byte, error) {
	// Nonblocking open prevents a regular-file-to-FIFO swap from blocking open.
	// Check the opened descriptor as well as discovery's Stat result.
	f, err := openCAFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("CA path %s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("CA file %s exceeds remaining byte limit %d", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("CA file %s exceeds remaining byte limit %d", path, limit)
	}
	return data, nil
}

// certificates decodes the configured CAs, keyed by nickname. The nickname derives
// from the decoded certificate, so reformatting a PEM or listing a CA twice never
// renames or drops it.
func (m *manager) certificates(ctx context.Context) (map[string][]byte, error) {
	files, err := m.files(ctx)
	if err != nil {
		return nil, err
	}
	want := map[string][]byte{}
	var total int64
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := readCAFile(f, min(maxCAFileBytes, maxCATotalBytes-total))
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
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
			if len(want) > maxCertificates {
				return nil, fmt.Errorf("more than %d CA certificates", maxCertificates)
			}
		}
	}
	return want, nil
}

// reconcile makes the database hold exactly the configured certificates. It does
// nothing when they are the ones the last successful sync applied, or when there is
// neither a certificate to import nor a database to clean up: the configured paths
// may exist empty (e.g. an empty Secret), and the agent's home must then stay as is.
// On error the change stays pending and the next call retries it.
func (m *manager) reconcile(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.inspect != nil {
		out, err := m.inspect(ctx, nil, "-L", "-d", "sql:"+m.dbDir())
		if err != nil {
			return fmt.Errorf("inspecting previous browser CAs: %w", err)
		}
		if len(managedCertificates(out)) == 0 {
			return nil
		}
	}
	want, err := m.certificates(ctx)
	if err != nil {
		// Leave the database alone until every CA file can be listed and read: syncing a
		// partial set would remove the CAs of the files that can't be.
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
		// The failed sync may have changed the database already: compare with it again
		// next time, not with what the last successful sync applied.
		m.applied = nil
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.prepareDBDir(); err != nil {
		return err
	}
	db := m.dbDir()
	dbArg := "sql:" + db
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
	existing := managedCertificates(out)

	var errs []error
	var added, removed int
	for nick, der := range want {
		if err := ctx.Err(); err != nil {
			return err
		}
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
	// Do not remove old trust after a failed import, including a timed-out command.
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for nick := range existing {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := want[nick]; ok {
			continue
		}
		if _, err := m.certs(ctx, nil, "-D", "-d", dbArg, "-n", nick); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", nick, err))
			continue
		}
		removed++
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}
	if added > 0 || removed > 0 {
		m.log.Infof("Custom CA certificates in the browser trust store: %d (added %d, removed %d)", len(want), added, removed)
	}
	return nil
}

func managedCertificates(out []byte) map[string]bool {
	existing := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasPrefix(fields[0], nicknamePrefix) {
			existing[fields[0]] = true
		}
	}

	return existing
}

// prepareDBDir repairs only NSS's directories and known database files. It never
// walks .pki: unrelated files keep their owners. All operations remain anchored
// at the browser home; final-component symlinks are rejected before repair.
func (m *manager) prepareDBDir() error {
	root, err := os.OpenRoot(m.home)
	if err != nil {
		return fmt.Errorf("opening the browser home: %w", err)
	}
	defer root.Close()
	for _, path := range []string{".pki", filepath.Join(".pki", "nssdb")} {
		if err := root.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("creating database directory: %w", err)
		}
		info, err := root.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("database directory %s is not a directory", path)
		}
		if m.owner != nil {
			if err := chownDatabasePath(root, path, m.owner, true); err != nil {
				return fmt.Errorf("changing database directory owner: %w", err)
			}
		}
	}
	if m.owner == nil {
		return nil
	}
	for _, name := range []string{"cert9.db", "key4.db", "pkcs11.txt", "cert9.db-journal", "cert9.db-wal", "cert9.db-shm", "key4.db-journal", "key4.db-wal", "key4.db-shm"} {
		path := filepath.Join(".pki", "nssdb", name)
		info, err := root.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("database file %s is not a regular file", path)
		}
		if err := chownDatabasePath(root, path, m.owner, false); err != nil {
			return fmt.Errorf("changing database file owner: %w", err)
		}
	}
	return nil
}

// run reconciles every interval until ctx is done. Without configured paths there is
// nothing to watch: it only retries a failed cleanup, and stops once one succeeds.
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
			continue
		}
		if len(m.paths) == 0 {
			return
		}
	}
}
