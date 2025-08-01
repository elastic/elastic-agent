// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fileutil

import (
	"os"
	"time"
)

// GetModTime returns file modification time
func GetModTime(fp string) (time.Time, error) {
	fi, err := os.Stat(fp)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}
