// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
)

// Check looks for created/modified/deleted/renamed files and returns an error
// if it finds any modifications. If executed in in verbose mode it will write
// the results of 'git diff' to stdout to indicate what changes have been made.
//
// It checks the file permissions of python test cases and YAML files.
// It checks .go source files using 'go vet'.
func Check() error {
	fmt.Println(">> check: Checking source code for common problems")

	mg.Deps(GoVet, CheckYAMLNotExecutable, CheckNoChanges)

	return nil
}

// CheckNoChanges returns an error if any files differ from what is committed.
// If executed in verbose mode it writes the output of 'git diff' to stdout.
func CheckNoChanges() error {
	changes, err := GitDiffIndex()
	if err != nil {
		return fmt.Errorf("failed to diff the git index: %w", err)
	}

	if len(changes) > 0 {
		if mg.Verbose() {
			if err := sh.RunV("git", "--no-pager", "diff", "--minimal"); err != nil {
				return fmt.Errorf("failed to run git diff: %w", err)
			}
		}

		return fmt.Errorf("some files are not up-to-date. "+
			"Usually running 'mage update' or 'mage addLicenseHeaders' "+
			"fixes the issues. Fix the issues, review and commit the changes. "+
			"Modified: %v", changes)
	}
	return nil
}

// GitDiffIndex returns a list of files that differ from what is committed.
// These could be files that were created, deleted, modified, or moved.
func GitDiffIndex() ([]string, error) {
	// Ensure the index is updated so that diff-index gives accurate results.
	if err := sh.Run("git", "update-index", "-q", "--refresh"); err != nil {
		return nil, err
	}

	out, err := sh.Output("git", "diff-index", "--name-only", "HEAD", "--", ".")
	if err != nil {
		return nil, err
	}
	return strings.FieldsFunc(out, func(r rune) bool { return r == '\n' }), nil
}

// CheckYAMLNotExecutable checks that no .yml or .yaml files are executable.
func CheckYAMLNotExecutable() error {
	if runtime.GOOS == "windows" {
		// Skip windows because it doesn't have POSIX permissions.
		return nil
	}

	executableYAMLFiles, err := FindFilesRecursive(func(path string, info os.FileInfo) bool {
		switch filepath.Ext(path) {
		default:
			return false
		case ".yml", ".yaml":
			return info.Mode().Perm()&0111 > 0
		}
	})
	if err != nil {
		return fmt.Errorf("failed search for YAML files: %w", err)
	}

	if len(executableYAMLFiles) > 0 {
		return fmt.Errorf("YAML files cannot be executable. Fix "+
			"permissions of %v", executableYAMLFiles)

	}
	return nil
}

// GoVet vets the .go source code using 'go vet'.
func GoVet() error {
	err := sh.RunV("go", "vet", "./...")
	if err != nil {
		return fmt.Errorf("failed running go vet, please fix the issues reported: %w", err)
	}
	return nil
}

// CheckLicenseHeaders checks license headers in .go files.
func CheckLicenseHeaders() error {
	fmt.Println(">> fmt - go-licenser: Checking for missing headers")
	mg.Deps(InstallGoLicenser)

	licenser := gotool.Licenser
	return licenser(
		licenser.Check(),
		licenser.License("Elasticv2"),
	)
}

// CheckLinksInFileAreLive checks if all links in a file are live.
func CheckLinksInFileAreLive(filename string) func() error {
	return func() error {
		// Skip for now until we can make this work without exceeding the GitHub rate limit
		// Related: https://github.com/elastic/elastic-agent/issues/8064
		return nil

		//fmt.Printf(">> check: Checking for invalid links in %q\n", filename)
		//mg.Deps(InstallGoLinkCheck)
		//
		//linkcheck := gotool.LinkCheck
		//return linkcheck(
		//	linkcheck.Path(filename),
		//)
	}
}
