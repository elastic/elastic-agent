// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	"fmt"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

var packageArchMap = map[string]string{
	"linux-binary-32":         "linux-x86.tar.gz",
	"linux-binary-64":         "linux-x86_64.tar.gz",
	"linux-binary-arm64":      "linux-arm64.tar.gz",
	"windows-binary-32":       "windows-x86.zip",
	"windows-binary-64":       "windows-x86_64.zip",
	"darwin-binary-32":        "darwin-x86_64.tar.gz",
	"darwin-binary-64":        "darwin-x86_64.tar.gz",
	"darwin-binary-arm64":     "darwin-aarch64.tar.gz",
	"darwin-binary-universal": "darwin-universal.tar.gz",
}

// Artifact provides info for fetching from artifact store.
type Artifact struct {
	Name     string
	Cmd      string
	Artifact string
}

// GetArtifactName constructs a path to a downloaded artifact
func GetArtifactName(a Artifact, version agtversion.ParsedSemVer, operatingSystem, arch string) (string, error) {
	key := fmt.Sprintf("%s-binary-%s", operatingSystem, arch)
	suffix, found := packageArchMap[key]
	if !found {
		return "", errors.New(fmt.Sprintf("'%s' is not a valid combination for a package", key), errors.TypeConfig)
	}

	return fmt.Sprintf("%s-%s-%s", a.Cmd, version.String(), suffix), nil
}

// GetArtifactPath returns a full path of artifact for a program in specific version
func GetArtifactPath(a Artifact, version agtversion.ParsedSemVer, operatingSystem, arch, targetDir string) (string, error) {
	artifactName, err := GetArtifactName(a, version, operatingSystem, arch)
	if err != nil {
		return "", err
	}

	fullPath := filepath.Join(targetDir, artifactName)
	return fullPath, nil
}
