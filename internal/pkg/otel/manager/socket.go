// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package manager

import (
	"fmt"
	"os"
	"path/filepath"
)

func socketURL(uuid string) string {
	return fmt.Sprintf("unix://%s", filepath.Join(os.TempDir(), fmt.Sprintf("otel-config-%s.sock", uuid)))
}
