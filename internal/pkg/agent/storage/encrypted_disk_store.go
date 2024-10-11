// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"

	"github.com/elastic/elastic-agent-libs/file"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/crypto"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const darwin = "darwin"

var encryptionDisabled bool

// DisableEncryptionDarwin disables storage encryption.
// Is needed for existing unit tests on Mac OS, because the system keychain requires sudo
func DisableEncryptionDarwin() {
	if runtime.GOOS == darwin {
		encryptionDisabled = true
	}
}

// EncryptedOptionFunc is an option configuration for the encrypted disk store.
type EncryptedOptionFunc func(s *EncryptedDiskStore)

// NewEncryptedDiskStore creates an encrypted disk store.
// Drop-in replacement for NewDiskStorage
func NewEncryptedDiskStore(ctx context.Context, target string, opts ...EncryptedOptionFunc) (Storage, error) {
	unprivileged := false
	hasRoot, err := utils.HasRoot()
	if err != nil {
		return nil, fmt.Errorf("error checking for root/Administrator privileges: %w", err)
	}
	if !hasRoot {
		unprivileged = true
		opts = append([]EncryptedOptionFunc{WithUnprivileged(unprivileged)}, opts...)
	}
	s := &EncryptedDiskStore{
		ctx:          ctx,
		target:       target,
		vaultPath:    paths.AgentVaultPath(),
		unprivileged: unprivileged,
	}
	for _, opt := range opts {
		opt(s)
	}
	if encryptionDisabled {
		var opts []DiskStoreOptionFunc
		if s.ownership != nil {
			opts = append(opts, DiskStoreWithOwnership(*s.ownership))
		}
		return NewDiskStore(target, opts...)
	}
	return s, nil
}

// WithVaultPath sets the path of the vault.
func WithVaultPath(vaultPath string) EncryptedOptionFunc {
	return func(s *EncryptedDiskStore) {
		s.vaultPath = vaultPath
	}
}

// WithUnprivileged sets if vault should be unprivileged.
func WithUnprivileged(unprivileged bool) EncryptedOptionFunc {
	return func(s *EncryptedDiskStore) {
		s.unprivileged = unprivileged
	}
}

// EncryptedStoreWithOwnership sets ownership for creating the files.
func EncryptedStoreWithOwnership(ownership utils.FileOwner) EncryptedOptionFunc {
	return func(s *EncryptedDiskStore) {
		s.ownership = &ownership
	}
}

// Exists will check if the encrypted disk store exists.
func (d *EncryptedDiskStore) Exists() (bool, error) {
	_, err := os.Stat(d.target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (d *EncryptedDiskStore) ensureKey(ctx context.Context) error {
	if d.key == nil {
		key, err := secret.GetAgentSecret(ctx, vault.WithVaultPath(d.vaultPath), vault.WithUnprivileged(d.unprivileged))
		if err != nil {
			return fmt.Errorf("could not get agent key: %w", err)
		}
		d.key = key.Value
	}
	return nil
}

// Save will read 'in' and write its contents encrypted to disk.
// If EncryptedDiskStore.Load() was called, the io.ReadCloser it returns MUST be
// closed before Save() can be called. It is so because Save() writes to a .tmp
// file then rotate the file to the target name to ensure that an error does not
// corrupt the previously written file.
// Specially on windows systems, if the original files is still open because of
// Load(), Save() would fail.
func (d *EncryptedDiskStore) Save(in io.Reader) error {
	// Ensure has agent key
	err := d.ensureKey(d.ctx)
	if err != nil {
		return errors.New(err, "failed to ensure key")
	}

	tmpFile := d.target + ".tmp"

	fd, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, permMask)
	if err != nil {
		return errors.New(err,
			fmt.Sprintf("could not save to %s", tmpFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, tmpFile))
	}

	// Always clean up the temporary file and ignore errors.
	defer os.Remove(tmpFile)

	// Wrap into crypto writer, reusing already existing crypto writer, open to other suggestions
	w, err := crypto.NewWriterWithDefaults(fd, d.key)
	if err != nil {
		fd.Close()
		return errors.New(err, "failed to open crypto writers")
	}

	if _, err := io.Copy(w, in); err != nil {
		if err := fd.Close(); err != nil {
			return errors.New(err, "could not close temporary file",
				errors.TypeFilesystem,
				errors.M(errors.MetaKeyPath, tmpFile))
		}

		return errors.New(err, "could not save content on disk",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, tmpFile))
	}

	if err := fd.Sync(); err != nil {
		return errors.New(err,
			fmt.Sprintf("could not sync temporary file %s", d.target),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, tmpFile))
	}

	if err := fd.Close(); err != nil {
		return errors.New(err, "could not close temporary file",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, tmpFile))
	}

	// fix the permissions of the temp file, ensuring that when the file is rotated in to place
	// it has the correct permissions (otherwise it is possible to be a permissions error, between
	// rotating the file and setting the permissions after).
	opts := []perms.OptFunc{perms.WithMask(permMask)}
	if d.ownership != nil {
		opts = append(opts, perms.WithOwnership(*d.ownership))
	}
	if err := perms.FixPermissions(tmpFile, opts...); err != nil {
		return errors.New(err,
			fmt.Sprintf("could not set permissions on temporary file %s", tmpFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, tmpFile))
	}

	if err := file.SafeFileRotate(d.target, tmpFile); err != nil {
		return errors.New(err,
			fmt.Sprintf("could not replace target file %s", d.target),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, d.target))
	}

	return nil
}

// Load returns an io.ReadCloser for the target.
func (d *EncryptedDiskStore) Load() (rc io.ReadCloser, err error) {
	fd, err := os.OpenFile(d.target, os.O_RDONLY, permMask)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// If file doesn't exist, return empty reader closer
			return io.NopCloser(bytes.NewReader([]byte{})), nil
		}
		return nil, errors.New(err,
			fmt.Sprintf("could not open %s", d.target),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, d.target))
	}

	// Close fd if there is an error upon return
	defer func() {
		if err != nil && fd != nil {
			_ = fd.Close()
		}
	}()

	// Ensure has agent key
	err = d.ensureKey(d.ctx)
	if err != nil {
		return nil, errors.New(err, "failed to ensure key during encrypted disk store Load")
	}

	return crypto.NewReaderWithDefaults(fd, d.key)
}
