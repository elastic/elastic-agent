// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package vault

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	keyLen    int = 32
	iterCount int = 12022
)

func (v *FileVault) encrypt(data []byte) ([]byte, error) {
	key, salt, err := deriveKey(v.seed, v.saltSize, nil)
	if err != nil {
		return nil, err
	}
	enc, err := aesgcm.Encrypt(key, data)
	if err != nil {
		return nil, err
	}
	return append(salt, enc...), nil
}

func (v *FileVault) decrypt(data []byte) ([]byte, error) {
	if len(data) < v.saltSize {
		return nil, syscall.EINVAL
	}
	salt, data := data[:v.saltSize], data[v.saltSize:]
	key, _, err := deriveKey(v.seed, v.saltSize, salt)
	if err != nil {
		return nil, err
	}
	return aesgcm.Decrypt(key, data)
}

func deriveKey(pw []byte, saltSize int, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := pbkdf2.Key(sha256.New, string(pw), salt, iterCount, keyLen)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func tightenPermissions(path string, ownership utils.FileOwner) error {
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
