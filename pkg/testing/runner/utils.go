// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/elastic/elastic-agent/pkg/core/process"
)

// WorkDir returns the current absolute working directory.
func WorkDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get work directory: %w", err)
	}
	wd, err = filepath.Abs(wd)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path to work directory: %w", err)
	}
	return wd, nil
}

func AttachOut(w io.Writer) process.CmdOption {
	return func(c *exec.Cmd) error {
		c.Stdout = w
		return nil
	}
}

func AttachErr(w io.Writer) process.CmdOption {
	return func(c *exec.Cmd) error {
		c.Stderr = w
		return nil
	}
}
