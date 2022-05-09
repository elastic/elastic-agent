// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows
// +build linux windows

package vault

import (
	"errors"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent-libs/file"
)

const seedFile = ".seed"

var ErrNonRootFileOwner = errors.New("non-root file owner")

var skipRootCheck bool

// DisableRootCheck is a hook to disable root owner check for .seed file
// This is needed for linux unit tests
func DisableRootCheck() {
	skipRootCheck = true
}

func isFileOwnerRoot(path string) (isOwnerRoot bool, err error) {
	if skipRootCheck || runtime.GOOS != "linux" {
		return true, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	stat, err := file.Wrap(info)
	if err != nil {
		return false, err
	}

	uid, _ := stat.UID()
	gid, _ := stat.GID()
	if uid == 0 && gid == 0 {
		return true, nil
	}

	return false, nil
}

func getSeed(path string) ([]byte, error) {
	fp := filepath.Join(path, seedFile)

	isOwnerRoot, err := isFileOwnerRoot(fp)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		isOwnerRoot = true
	}

	if !isOwnerRoot {
		return nil, ErrNonRootFileOwner
	}

	b, err := ioutil.ReadFile(fp)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	if len(b) != 0 {
		return b, nil
	}

	seed, err := NewKey(AES256)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(fp, seed, 0600)
	if err != nil {
		return nil, err
	}

	return seed, nil
}
