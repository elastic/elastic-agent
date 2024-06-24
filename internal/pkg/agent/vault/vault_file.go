// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

type FileVault struct {
	path string
	seed []byte

	lockRetryDelay time.Duration
	lock           *flock.Flock
}

// NewFileVault creates the file-based vault store
func NewFileVault(ctx context.Context, options Options) (v *FileVault, err error) {
	path := options.vaultPath
	dir := filepath.Dir(path)

	// If there is no specific path then get the executable directory
	if dir == "." {
		exefp, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("could not get executable path: %w", err)
		}
		dir = filepath.Dir(exefp)
		path = filepath.Join(dir, path)
	}

	if options.readonly {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			return nil, fs.ErrNotExist
		}
	} else {
		err := os.MkdirAll(path, 0750)
		if err != nil {
			return nil, fmt.Errorf("failed to create vault path: %v, err: %w", path, err)
		}
		err = tightenPermissions(path, options.ownership)
		if err != nil {
			return nil, err
		}
	}

	r := &FileVault{
		path:           path,
		lockRetryDelay: options.lockRetryDelay,
		lock:           flock.New(filepath.Join(path, lockFile)),
	}

	err = r.tryLock(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = r.unlockAndJoinErrors(err)
	}()

	r.seed, err = getOrCreateSeed(path, options.readonly)
	if err != nil {
		return nil, fmt.Errorf("could not get or create seed for the vault at %s: %w", path, err)
	}

	return r, nil
}

// Set stores the key in the vault store
func (v *FileVault) Set(ctx context.Context, key string, data []byte) (err error) {
	enc, err := v.encrypt(data)
	if err != nil {
		return fmt.Errorf("vault Set: could not encrypt key: %w", err)
	}

	err = v.tryLock(ctx)
	if err != nil {
		return fmt.Errorf("vault Set: could acquire lock: %w", err)
	}
	defer func() {
		err = v.unlockAndJoinErrors(err)
		if err != nil {
			err = fmt.Errorf("vault Set: unlockAndJoinErrors failed: %w", err)
		}
	}()

	err = writeFile(v.filepathFromKey(key), enc)
	if err != nil {
		return fmt.Errorf("vaukt: could not write key to file: %w", err)
	}
	return nil
}

// Get retrieves the key from the vault store
func (v *FileVault) Get(ctx context.Context, key string) (dec []byte, err error) {
	err = v.tryRLock(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = v.unlockAndJoinErrors(err)
	}()

	enc, err := os.ReadFile(v.filepathFromKey(key))
	if err != nil {
		return nil, err
	}

	return v.decrypt(enc)
}

// Exists checks if the key exists
func (v *FileVault) Exists(ctx context.Context, key string) (ok bool, err error) {
	err = v.tryRLock(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		err = v.unlockAndJoinErrors(err)
	}()

	if _, err = os.Stat(v.filepathFromKey(key)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Remove removes the key
func (v *FileVault) Remove(ctx context.Context, key string) (err error) {
	err = v.tryLock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		err = v.unlockAndJoinErrors(err)
	}()

	return os.RemoveAll(v.filepathFromKey(key))
}

// Close closes the vault store
// Noop for non-darwin implementation
func (v *FileVault) Close() error {
	return nil
}

// fileNameFromKey returns the filename as a hash of the vault seed combined with the key
// This ties the key with the vault seed eliminating the chance of attempting
// to decrypt the key for the wrong vault seed value.
func fileNameFromKey(seed []byte, key string) string {
	hash := sha256.Sum256(append(seed, []byte(key)...))
	return hex.EncodeToString(hash[:])
}

func (v *FileVault) filepathFromKey(key string) string {
	return filepath.Join(v.path, fileNameFromKey(v.seed, key))
}

// try to acquire exclusive lock
func (v *FileVault) tryLock(ctx context.Context) error {
	_, err := v.lock.TryLockContext(ctx, v.lockRetryDelay)
	if err != nil {
		return fmt.Errorf("failed to acquire exclusive lock: %v, err: %w", v.lock.Path(), err)
	}
	return nil
}

// try to acquire shared lock
func (v *FileVault) tryRLock(ctx context.Context) error {
	_, err := v.lock.TryRLockContext(ctx, v.lockRetryDelay)
	if err != nil {
		return fmt.Errorf("failed to acquire shared lock: %v, err: %w", v.lock.Path(), err)
	}
	return nil
}

// unlockAndJoinErrors Helper function that unlocks the file lock and returns joined error
func (v *FileVault) unlockAndJoinErrors(err error) error {
	return errors.Join(err, v.lock.Unlock())
}
