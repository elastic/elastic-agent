// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fileutil

import (
	"errors"
	"io/fs"
	"os"
	"time"
)

// FileExists returns true if file/dir exists
func FileExists(fp string) (bool, error) {
	_, err := os.Stat(fp)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetModTime returns file modification time
func GetModTime(fp string) (time.Time, error) {
	fi, err := os.Stat(fp)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

// GetModTimeExists returns file modification time and existence status
// Returns no error if the file doesn't exists
func GetModTimeExists(fp string) (time.Time, bool, error) {
	modTime, err := GetModTime(fp)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return modTime, false, nil
		}
		return modTime, false, err
	}
	return modTime, true, nil
}
