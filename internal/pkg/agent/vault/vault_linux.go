// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux
// +build linux

package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
)

const saltSize = 8

type Vault struct {
	path string
	key  []byte
}

// Open initializes the vault store
func New(path string) (*Vault, error) {
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

	err := os.MkdirAll(path, 0750)
	if err != nil {
		return nil, err
	}

	key, err := getSeed(path)
	if err != nil {
		return nil, err
	}

	return &Vault{
		path: path,
		key:  key,
	}, nil
}

// Close closes the valut store
// Noop on linux
func (v *Vault) Close() error {
	return nil
}

// Set stores the key in the vault store
func (v *Vault) Set(key string, data []byte) error {
	enc, err := v.encrypt(data)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(v.filepathFromKey(key), enc, 0600)
}

// Get retrieves the key from the vault store
func (v *Vault) Get(key string) ([]byte, error) {
	enc, err := ioutil.ReadFile(v.filepathFromKey(key))
	if err != nil {
		return nil, err
	}

	return v.decrypt(enc)
}

// Exists checks if the key exists
func (v *Vault) Exists(key string) (ok bool, err error) {
	if _, err = os.Stat(v.filepathFromKey(key)); err == nil {
		ok = true
	} else if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return ok, err
}

// Remove removes the key
func (v *Vault) Remove(key string) error {
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
	return filepath.Join(v.path, fileNameFromKey(key))
}

func fileNameFromKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}
