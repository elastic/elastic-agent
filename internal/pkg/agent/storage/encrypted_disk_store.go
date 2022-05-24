// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package storage

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"

	"github.com/hectane/go-acl"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/crypto"
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

type OptionFunc func(s *EncryptedDiskStore)

// NewEncryptedDiskStore creates an encrypted disk store.
// Drop-in replacement for NewDiskStorage
func NewEncryptedDiskStore(target string, opts ...OptionFunc) Storage {
	if encryptionDisabled {
		return NewDiskStore(target)
	}
	s := &EncryptedDiskStore{
		target:    target,
		vaultPath: paths.AgentVaultPath(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithVaultPath(vaultPath string) OptionFunc {
	return func(s *EncryptedDiskStore) {
		if runtime.GOOS == darwin {
			return
		}
		s.vaultPath = vaultPath
	}
}

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

func (d *EncryptedDiskStore) ensureKey() error {
	if d.key == nil {
		key, err := secret.GetAgentSecret(secret.WithVaultPath(d.vaultPath))
		if err != nil {
			return err
		}
		d.key = key.Value
	}
	return nil
}

func (d *EncryptedDiskStore) Save(in io.Reader) error {
	// Ensure has agent key
	err := d.ensureKey()
	if err != nil {
		return err
	}

	tmpFile := d.target + ".tmp"

	fd, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perms)
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
		return err
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

	if err := file.SafeFileRotate(d.target, tmpFile); err != nil {
		return errors.New(err,
			fmt.Sprintf("could not replace target file %s", d.target),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, d.target))
	}

	if err := acl.Chmod(d.target, perms); err != nil {
		return errors.New(err,
			fmt.Sprintf("could not set permissions target file %s", d.target),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, d.target))
	}

	return nil
}

func (d *EncryptedDiskStore) Load() (rc io.ReadCloser, err error) {
	fd, err := os.OpenFile(d.target, os.O_RDONLY, perms)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// If file doesn't exists, return empty reader closer
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
	err = d.ensureKey()
	if err != nil {
		return nil, err
	}

	return crypto.NewReaderWithDefaults(fd, d.key)
}
