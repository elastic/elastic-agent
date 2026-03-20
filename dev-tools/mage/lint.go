// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/magefile/mage/sh"
)

// ParseToolVersions parses a .tool-versions file and returns a map of tool
// names to their versions. See https://asdf-vm.com/manage/configuration.html#tool-versions.
func ParseToolVersions(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	versions := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			versions[fields[0]] = fields[1]
		}
	}
	return versions, scanner.Err()
}

// GolangciLintVersion reads the golangci-lint version from .tool-versions and
// returns it prefixed with "v" (e.g. "v2.5.0").
func GolangciLintVersion() (string, error) {
	versions, err := ParseToolVersions(".tool-versions")
	if err != nil {
		return "", err
	}
	ver, ok := versions["golangci-lint"]
	if !ok {
		return "", fmt.Errorf("golangci-lint version not found in .tool-versions")
	}
	return "v" + ver, nil
}

// InstallGolangciLint downloads and installs golangci-lint using the version
// specified in .tool-versions.
func InstallGolangciLint() error {
	ver, err := GolangciLintVersion()
	if err != nil {
		return err
	}
	fmt.Printf(">> install golangci-lint %s\n", ver)
	return sh.RunV("bash", "-c",
		fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s %s", ver))
}

// Lint runs golangci-lint on current changes only.
func Lint() error {
	return sh.RunV("./bin/golangci-lint", "run", "-v", "--timeout=30m", "--whole-files", "--new")
}

// LintAll runs golangci-lint on the whole codebase.
func LintAll() error {
	return sh.RunV("./bin/golangci-lint", "run", "-v", "--timeout=30m")
}
