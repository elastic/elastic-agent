// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	devtools "github.com/elastic/elastic-agent-poc/dev-tools/mage"
)

// PackageSystemTests packages the python system tests results
func PackageSystemTests() error {
	excludeds := []string{".ci", ".git", ".github", "vendor", "dev-tools"}

	// include run as it's the directory we want to compress
	systemTestsDir := filepath.Join("build", "system-tests", "run")
	files, err := devtools.FindFilesRecursive(func(path string, _ os.FileInfo) bool {
		base := filepath.Base(path)
		for _, excluded := range excludeds {
			if strings.HasPrefix(base, excluded) {
				return false
			}
		}

		return strings.HasPrefix(path, systemTestsDir)
	})
	if err != nil {
		return err
	}

	if len(files) == 0 {
		fmt.Printf(">> there are no system test files under %s", systemTestsDir)
		return nil
	}

	// create a plain directory layout for all beats
	beat := devtools.MustExpand("{{ repo.SubDir }}")
	beat = strings.ReplaceAll(beat, string(os.PathSeparator), "-")

	targetFile := devtools.MustExpand("{{ elastic_beats_dir }}/build/system-tests-" + beat + ".tar.gz")
	parent := filepath.Dir(targetFile)
	if !fileExists(parent) {
		fmt.Printf(">> creating parent dir: %s", parent)
		os.Mkdir(parent, 0750)
	}

	err = devtools.Tar(systemTestsDir, targetFile)
	if err != nil {
		fmt.Printf(">> %s", err)
		return err
	}

	return nil
}

// fileExists returns true if the specified file exists.
func fileExists(file string) bool {
	_, err := os.Stat(file)
	return !os.IsNotExist(err)
}
