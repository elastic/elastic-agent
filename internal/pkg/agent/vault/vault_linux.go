// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/crypto/pbkdf2"
)

const (
	lockFile = `.lock`
	saltSize = 8
)

type Vault struct {
	path string
	key  []byte

	retryDelay time.Duration
	lock       *flock.Flock
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
	}

	r := &Vault{
		path:       path,
		retryDelay: options.retryDelay,
		lock:       flock.New(filepath.Join(path, lockFile)),
	}

	err = r.tryLock(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = r.unlock(err)
	}()

	r.key, err = getOrCreateSeed(path, options.readonly)
	if err != nil {
		return nil, fmt.Errorf("could not get seed to create new valt: %w", err)
	}

	return r, nil
}

// try to acquire exclusive lock
func (v *Vault) tryLock(ctx context.Context) error {
	_, err := v.lock.TryLockContext(ctx, v.retryDelay)
	if err != nil {
		return fmt.Errorf("failed to acquire exclusive lock: %v, err: %w", v.lock.Path(), err)
	}
	return err
}

// try to acquire shared lock
func (v *Vault) tryRLock(ctx context.Context) error {
	_, err := v.lock.TryRLockContext(ctx, v.retryDelay)
	if err != nil {
		return fmt.Errorf("failed to acquire shared lock: %v, err: %w", v.lock.Path(), err)
	}
	return err
}

// unlock unlocks the file lock and preserves the original error if there was a error
func (v *Vault) unlock(err error) error {
	unerr := v.lock.Unlock()
	if err != nil {
		return err
	}
	return unerr
}

// Close closes the valut store
// Noop on linux
func (v *Vault) Close() error {
	return nil
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

	if _, err = os.Stat(v.filepathFromKey(key)); err == nil {
		ok = true
	} else if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return ok, err
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

func (v *Vault) encrypt(data []byte) ([]byte, error) {
	key, salt, err := deriveKey(v.key, nil)
	if err != nil {
		return nil, err
	}
	enc, err := Encrypt(key, data)
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
	key, _, err := deriveKey(v.key, salt)
	if err != nil {
		return nil, err
	}
	return Decrypt(key, data)
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

func (v *Vault) filepathFromKey(key string) string {
	return filepath.Join(v.path, fileNameFromKey(v.key, key))
}
