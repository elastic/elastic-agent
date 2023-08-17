// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/pbkdf2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

const (
	saltSize = 8
)

func (v *Vault) encrypt(data []byte) ([]byte, error) {
	key, salt, err := deriveKey(v.seed, nil)
	if err != nil {
		return nil, err
	}
	enc, err := aesgcm.Encrypt(key, data)
	if err != nil {
		return nil, err
	}
	return append(salt, enc...), nil
}

func (v *Vault) decrypt(data []byte) ([]byte, error) {
	if len(data) < saltSize {
		return nil, syscall.EINVAL
	}
	salt, data := data[:saltSize], data[saltSize:]
	key, _, err := deriveKey(v.seed, salt)
	if err != nil {
		return nil, err
	}
	return aesgcm.Decrypt(key, data)
}

func deriveKey(pw []byte, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	return pbkdf2.Key(pw, salt, 12022, 32, sha256.New), salt, nil
}

func tightenPermissions(path string) error {
	// Noop for linx
	return nil
}

// writeFile "atomic" file write, utilizes temp file and replace
func writeFile(fp string, data []byte) (err error) {
	dir, fn := filepath.Split(fp)
	if dir == "" {
		dir = "."
	}

	f, err := os.CreateTemp(dir, fn)
	if err != nil {
		return fmt.Errorf("failed creating temp file: %w", err)
	}
	defer func() {
		rerr := os.Remove(f.Name())
		if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("cleanup failed, could not remove temp file: %w", rerr))
		}
	}()
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("failed writing temp file: %w", err)
	}

	err = f.Sync()
	if err != nil {
		return fmt.Errorf("failed syncing temp file: %w", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("failed closing temp file: %w", err)
	}

	return os.Rename(f.Name(), fp)
}
