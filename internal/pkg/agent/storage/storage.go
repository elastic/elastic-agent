// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package storage

import (
	"io"
	"os"
)

const perms os.FileMode = 0600

// Store saves the io.Reader.
type Store interface {
	// Save the io.Reader.
	Save(io.Reader) error
}

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

type EncryptedDiskStore struct {
	target    string
	vaultPath string
	key       []byte
}
