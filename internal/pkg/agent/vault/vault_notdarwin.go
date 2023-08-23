// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !darwin

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

const (
	// defaultFlockRetryDelay default file lock retry delay
	defaultFlockRetryDelay = 10 * time.Millisecond

	// lock file name
	lockFile = `.lock`
)

type Vault struct {
	path string
	seed []byte

	lockRetryDelay time.Duration
	lock           *flock.Flock
}

// New creates the vault store
func New(ctx context.Context, path string, opts ...OptionFunc) (v *Vault, err error) {
	options := applyOptions(opts...)
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
		err = tightenPermissions(path)
		if err != nil {
			return nil, err
		}
	}

	r := &Vault{
		path:           path,
		lockRetryDelay: options.lockRetryDelay,
		lock:           flock.New(filepath.Join(path, lockFile)),
	}

	err = r.tryLock(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = r.unlock(err)
	}()

	r.seed, err = getOrCreateSeed(path, options.readonly)
	if err != nil {
		return nil, fmt.Errorf("could not get or create seed for the vault at %s: %w", path, err)
	}

	return r, nil
}

// Set stores the key in the vault store
func (v *Vault) Set(ctx context.Context, key string, data []byte) (err error) {
	enc, err := v.encrypt(data)
	if err != nil {
		return err
	}

	err = v.tryLock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		err = v.unlock(err)
	}()

	return writeFile(v.filepathFromKey(key), enc)
}

// Get retrieves the key from the vault store
func (v *Vault) Get(ctx context.Context, key string) (dec []byte, err error) {
	err = v.tryRLock(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = v.unlock(err)
	}()

	enc, err := os.ReadFile(v.filepathFromKey(key))
	if err != nil {
		return nil, err
	}

	return v.decrypt(enc)
}

// Exists checks if the key exists
func (v *Vault) Exists(ctx context.Context, key string) (ok bool, err error) {
	err = v.tryRLock(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		err = v.unlock(err)
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
func (v *Vault) Remove(ctx context.Context, key string) (err error) {
	err = v.tryLock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		err = v.unlock(err)
	}()

	return os.RemoveAll(v.filepathFromKey(key))
}

// Close closes the vault store
// Noop for non-darwin implementation
func (v *Vault) Close() error {
	return nil
}

// applyOptions applies options for windows and linux, not used for darwin implementation
func applyOptions(opts ...OptionFunc) Options {
	options := Options{
		lockRetryDelay: defaultFlockRetryDelay,
	}

	for _, opt := range opts {
		opt(&options)
	}

	return options
}

// fileNameFromKey returns the filename as a hash of the vault seed combined with the key
// This ties the key with the vault seed eliminating the chance of attempting
// to decrypt the key for the wrong vault seed value.
func fileNameFromKey(seed []byte, key string) string {
	hash := sha256.Sum256(append(seed, []byte(key)...))
	return hex.EncodeToString(hash[:])
}

func (v *Vault) filepathFromKey(key string) string {
	return filepath.Join(v.path, fileNameFromKey(v.seed, key))
}

// try to acquire exclusive lock
func (v *Vault) tryLock(ctx context.Context) error {
	_, err := v.lock.TryLockContext(ctx, v.lockRetryDelay)
	if err != nil {
		return fmt.Errorf("failed to acquire exclusive lock: %v, err: %w", v.lock.Path(), err)
	}
	return nil
}

// try to acquire shared lock
func (v *Vault) tryRLock(ctx context.Context) error {
	_, err := v.lock.TryRLockContext(ctx, v.lockRetryDelay)
	if err != nil {
		return fmt.Errorf("failed to acquire shared lock: %v, err: %w", v.lock.Path(), err)
	}
	return nil
}

// unlock unlocks the file lock and preserves the original error if there was a error
func (v *Vault) unlock(err error) error {
	return errors.Join(err, v.lock.Unlock())
}
