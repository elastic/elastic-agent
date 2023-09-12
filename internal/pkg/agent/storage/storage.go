// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package storage

import (
	"context"
	"io"
	"os"
)

const perms os.FileMode = 0600

// Store saves the io.Reader.
type Store interface {
	// Save the io.Reader.
	Save(io.Reader) error
}

// Storage interacts with on-disk data stores.
type Storage interface {
	Store

	// Load return an io.ReadCloser for the target store.
	Load() (io.ReadCloser, error)

	// Exists checks if the store exists.
	Exists() (bool, error)
}

// DiskStore takes a persistedConfig and save it to a temporary files and replace the target file.
type DiskStore struct {
	target string
}

// EncryptedDiskStore encrypts config when saving to disk.
// When saving it will save to a temporary file then replace the target file.
type EncryptedDiskStore struct {
	ctx       context.Context
	target    string
	vaultPath string
	key       []byte
}
