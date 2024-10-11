// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package version

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/version"
)

// GetDefaultVersion returns the current libbeat version.
// This method is in a separate file as the version.go file is auto generated
func GetDefaultVersion() string {
	if qualifier == "" {
		return defaultBeatVersion
	}
	return defaultBeatVersion + "-" + qualifier
}

var (
	buildTime            = "unknown"
	commit               = "unknown"
	qualifier            = ""
	packageVersion       = ""
	parsedPackageVersion *version.ParsedSemVer
)

const PackageVersionFileName = "package.version"

var versionInitError error

func init() {
	versionInitError = InitVersionInformation()
}

// InitVersionError returns any error that might have occurred during package init
func InitVersionError() error {
	return versionInitError
}

// InitVersionInformation initialize the package version string reading from the
// corresponding file. This function is not thread-safe and should be called once
// before any calls to Version() has been done
func InitVersionInformation() error {
	packageVersionFilePath, err := GetAgentPackageVersionFilePath()
	if err != nil {
		// fallback to default binary version
		packageVersion = GetDefaultVersion()
		return fmt.Errorf("retrieving package version file path: %w", err)
	}
	versionBytes, err := os.ReadFile(packageVersionFilePath)
	if err != nil {
		fallbackToDefaultVersion()
		return fmt.Errorf("reading package version from file %q: %w", packageVersionFilePath, err)
	}
	fileVersion := strings.TrimSpace(string(versionBytes))
	// Set the version from the file content
	packageVersion = fileVersion
	parsedPackageVersion, err = version.ParseVersion(fileVersion)
	if err != nil {
		fallbackToDefaultVersion()
		return fmt.Errorf("parsing version %q: %w", fileVersion, err)
	}
	return nil
}

func fallbackToDefaultVersion() {
	// fallback to default binary version
	packageVersion = GetDefaultVersion()
	// guaranteed to be correct as it is set in code
	parsedPackageVersion, _ = version.ParseVersion(GetDefaultVersion())
}

// GetAgentPackageVersion retrieves the version saved in package.version in the same
// directory as the agent executable.
// This function must be called AFTER InitVersionInformation() has initialized the module vars
func GetAgentPackageVersion() string {
	return packageVersion
}

// GetParsedAgentPackageVersion retrieves the version saved in package.version in the same
// directory as the agent executable and returns it as a parsed semver object.
// This function must be called AFTER InitVersionInformation() has initialized the module vars
func GetParsedAgentPackageVersion() *version.ParsedSemVer {
	return parsedPackageVersion
}

// GetAgentPackageVersionFilePath returns the path where the package version file
// should be located (side by side with the currently executing binary)
func GetAgentPackageVersionFilePath() (string, error) {
	execPath, err := getCurrentExecutablePath()
	if err != nil {
		return "", fmt.Errorf("detecting current executable path: %w", err)
	}

	dirPath := filepath.Dir(execPath)

	if runtime.GOOS == "darwin" {
		// On Mac the path is different because of package signing issues
		// we have to go outside the elastic-agent.app directory
		appDirIndex := strings.Index(dirPath, "/elastic-agent.app/")
		if appDirIndex != -1 {
			dirPath = dirPath[:appDirIndex]
		}
	}

	return filepath.Join(dirPath, PackageVersionFileName), nil
}

func getCurrentExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("retrieving current process executable: %w", err)
	}
	evalPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", fmt.Errorf("evaluating symlinks to current process executable: %w", err)
	}

	return evalPath, nil
}

// BuildTime exposes the compile-time build time information.
// It will represent the zero time instant if parsing fails.
func BuildTime() time.Time {
	t, err := time.Parse(time.RFC3339, buildTime)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Commit exposes the compile-time commit hash.
func Commit() string {
	return commit
}
