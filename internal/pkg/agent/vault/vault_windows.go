// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package vault

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/billgraziano/dpapi"
	"github.com/gofrs/flock"
	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

const lockFile = `.lock`

type Vault struct {
	path    string
	entropy []byte

	retryDelay time.Duration
	lock       *flock.Flock
}

// Open initializes the vault store
func New(ctx context.Context, path string, opts ...OptionFunc) (v *Vault, err error) {
	options := applyOptions(opts...)
	dir := filepath.Dir(path)

	// If there is no specific path then get the executable directory
	if dir == "." {
		exefp, err := os.Executable()
		if err != nil {
			return nil, err
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
			return nil, err
		}
		err = systemAdministratorsOnly(path, false)
		if err != nil {
			return nil, err
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

	r.entropy, err = getOrCreateSeed(path, options.readonly)
	if err != nil {
		return nil, err
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

// Close closes the vault store
// Noop on windows
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

	return ioutil.WriteFile(v.filepathFromKey(key), enc, 0600)
}

// Get retrieves the key from the vault store
func (v *Vault) Get(ctx context.Context, key string) ([]byte, error) {
	err = v.tryRLock(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = v.unlock(err)
	}()

	enc, err := ioutil.ReadFile(v.filepathFromKey(key))
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
	return dpapi.EncryptBytesMachineLocalEntropy(data, v.entropy)
}

func (v *Vault) decrypt(data []byte) ([]byte, error) {
	return dpapi.DecryptBytesEntropy(data, v.entropy)
}

func (v *Vault) filepathFromKey(key string) string {
	return filepath.Join(v.path, fileNameFromKey(v.entropy, key))
}

func systemAdministratorsOnly(path string, inherit bool) error {
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	administratorsSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}

	// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
	return acl.Apply(
		path, true, inherit,
		acl.GrantSid(0xF10F0000, systemSID), // full control of all acl's
		acl.GrantSid(0xF10F0000, administratorsSID))
}
