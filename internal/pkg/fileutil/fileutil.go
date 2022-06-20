// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fileutil

import (
	"os"
	"time"
)

// FileExists returns true if file/dir exists
func FileExists(fp string) (ok bool, err error) {
	if _, err := os.Stat(fp); err == nil {
		ok = true
	} else if os.IsNotExist(err) {
		err = nil
	}
	return ok, err
}

// GetModTime returns file modification time
func GetModTime(fp string) (time.Time, error) {
	fi, err := os.Stat(fp)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), err
}

// GetModTimeExists returns file modification time and existance status
// Returns no error if the file doesn't exists
func GetModTimeExists(fp string) (modTime time.Time, exists bool, err error) {
	modTime, err = GetModTime(fp)
	if err != nil {
		if os.IsNotExist(err) {
			return modTime, false, nil
		}
		return modTime, false, err
	}
	return modTime, true, nil
}
