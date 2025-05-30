// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

// Tidy runs go mod tidy on all go.mod recursively inside the elastic-agent repository.
func Tidy() error {
	goModFiles, err := devtools.FindFilesRecursive(func(path string, _ os.FileInfo) bool {
		return filepath.Base(path) == "go.mod"
	})
	if err != nil {
		return err
	}
	for _, file := range goModFiles {
		dir, err := filepath.Abs(filepath.Dir(file))
		if err != nil {
			return fmt.Errorf("tidy: error getting absolute dir: %w", err)
		}
		fmt.Printf(">> tidy: Running go mod tidy inside %s\n", dir)
		cmd := exec.Command(mg.GoCmd(), "mod", "tidy", "-v")
		cmd.Dir = dir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("tidy: error running go mod tidy: %w", err)
		}
	}
	return nil
}
