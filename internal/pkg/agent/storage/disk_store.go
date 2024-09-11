// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"fmt"
	"io"
	"os"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// DiskStoreOptionFunc is an option configuration for the disk store.
type DiskStoreOptionFunc func(s *DiskStore)

// DiskStoreWithOwnership sets ownership for creating the files.
func DiskStoreWithOwnership(ownership utils.FileOwner) DiskStoreOptionFunc {
	return func(s *DiskStore) {
		s.ownership = &ownership
	}
}

// NewDiskStore creates an unencrypted disk store.
func NewDiskStore(target string, opts ...DiskStoreOptionFunc) (*DiskStore, error) {
	s := &DiskStore{target: target}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Exists check if the store file exists on the disk
func (d *DiskStore) Exists() (bool, error) {
	_, err := os.Stat(d.target)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Delete deletes the store file on the disk
func (d *DiskStore) Delete() error {
	return os.Remove(d.target)
}

// Save accepts a persistedConfig and saved it to a target file, to do so we will
// make a temporary files if the write is successful we are replacing the target file with the
// original content.
func (d *DiskStore) Save(in io.Reader) error {
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

	if _, err := io.Copy(fd, in); err != nil {
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
			fmt.Sprintf("could not sync temporary file %s", tmpFile),
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

// Load return a io.ReadCloser for the target file.
func (d *DiskStore) Load() (io.ReadCloser, error) {
	fd, err := os.OpenFile(d.target, os.O_RDONLY|os.O_CREATE, permMask)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not open %s", d.target),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, d.target))
	}
	return fd, nil
}
