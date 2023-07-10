// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package vault

import (
	"errors"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/billgraziano/dpapi"
	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

type Vault struct {
	path    string
	entropy []byte
	mx      sync.Mutex
}

// Open initializes the vault store
func New(path string, opts ...OptionFunc) (v *Vault, err error) {
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

	entropy, err := getOrCreateSeed(path, options.readonly)
	if err != nil {
		return nil, err
	}

	return &Vault{
		path:    path,
		entropy: entropy,
	}, nil
}

// Close closes the valut store
// Noop on windows
func (v *Vault) Close() error {
	return nil
}

// Set stores the key in the vault store
func (v *Vault) Set(key string, data []byte) error {
	enc, err := v.encrypt(data)
	if err != nil {
		return err
	}

	v.mx.Lock()
	defer v.mx.Unlock()

	return ioutil.WriteFile(v.filepathFromKey(key), enc, 0600)
}

// Get retrieves the key from the vault store
func (v *Vault) Get(key string) ([]byte, error) {
	v.mx.Lock()
	defer v.mx.Unlock()

	enc, err := ioutil.ReadFile(v.filepathFromKey(key))
	if err != nil {
		return nil, err
	}

	return v.decrypt(enc)
}

// Exists checks if the key exists
func (v *Vault) Exists(key string) (ok bool, err error) {
	v.mx.Lock()
	defer v.mx.Unlock()

	if _, err = os.Stat(v.filepathFromKey(key)); err == nil {
		ok = true
	} else if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return ok, err
}

// Remove removes the key
func (v *Vault) Remove(key string) error {
	v.mx.Lock()
	defer v.mx.Unlock()

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
