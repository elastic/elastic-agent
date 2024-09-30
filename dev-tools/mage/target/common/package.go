// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

// PackageSystemTests packages the python system tests results
func PackageSystemTests() error {
	excludes := []string{".ci", ".git", ".github", "vendor", "dev-tools"}

	// include run and docker-logs as they are the directories we want to compress
	systemTestsDir := filepath.Join("build", "system-tests")
	systemTestsRunDir := filepath.Join(systemTestsDir, "run")
	systemTestsLogDir := filepath.Join(systemTestsDir, "docker-logs")
	files, err := devtools.FindFilesRecursive(func(path string, _ os.FileInfo) bool {
		base := filepath.Base(path)
		for _, ex := range excludes {
			if strings.HasPrefix(base, ex) {
				return false
			}
		}

		return strings.HasPrefix(path, systemTestsRunDir) || strings.HasPrefix(path, systemTestsLogDir)
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
