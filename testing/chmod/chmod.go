// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package chmod

import (
	"io/fs"
	"os"
)

func Chmod(name string, mode fs.FileMode) error {
	return os.Chmod(name, mode)
}
