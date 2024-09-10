// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"context"
	"io"
	"os"

	"github.com/elastic/elastic-agent/pkg/utils"
)

const permMask os.FileMode = 0600

// Store saves the io.Reader.
type Store interface {
	// Save the io.Reader. Depending on the underlying implementation, if
	// Storage.Load() was called, the io.ReadCloser MUST be closed before Save()
	// can be called.
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
	target    string
	ownership *utils.FileOwner
}

// EncryptedDiskStore encrypts config when saving to disk.
// When saving it will save to a temporary file then replace the target file.
type EncryptedDiskStore struct {
	ctx          context.Context
	target       string
	vaultPath    string
	key          []byte
	unprivileged bool
	ownership    *utils.FileOwner
}
