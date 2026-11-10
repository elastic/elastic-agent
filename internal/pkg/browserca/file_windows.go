// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package browserca

import (
	"errors"
	"os"
)

// Browser CA import is disabled on Windows.
func openCAFile(path string) (*os.File, error) {
	return os.Open(path)
}

func chownDatabasePath(_ *os.Root, _ string, _ *owner, _ bool) error {
	return errors.New("browser CA ownership changes are unsupported on Windows")
}
