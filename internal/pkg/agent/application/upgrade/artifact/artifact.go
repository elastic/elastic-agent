// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

var packageArchMap = map[string]string{
	"linux-binary-32":         "linux-x86.tar.gz",
	"linux-binary-64":         "linux-x86_64.tar.gz",
	"linux-binary-arm64":      "linux-arm64.tar.gz",
	"windows-binary-32":       "windows-x86.zip",
	"windows-binary-64":       "windows-x86_64.zip",
	"windows-binary-arm64":    "windows-arm64.zip",
	"darwin-binary-32":        "darwin-x86_64.tar.gz",
	"darwin-binary-64":        "darwin-x86_64.tar.gz",
	"darwin-binary-arm64":     "darwin-aarch64.tar.gz",
	"darwin-binary-universal": "darwin-universal.tar.gz",
}

// Artifact provides info for fetching from artifact store.
type Artifact struct {
	Name     string
	Version  *agtversion.ParsedSemVer
	FileName string
}

func New(name string, fips bool, version *agtversion.ParsedSemVer, os, arch string) (Artifact, error) {
	parts := []string{name}
	if fips {
		parts = append(parts, "fips")
	}

	key := fmt.Sprintf("%s-binary-%s", os, arch)
	suffix, found := packageArchMap[key]
	if !found {
		return Artifact{}, errors.New(fmt.Sprintf("'%s' is not a valid combination for a package", key), errors.TypeConfig)
	}

	if version.IsSnapshot() {
		parts = append(parts, version.VersionWithPrerelease(), suffix)
	} else {
		parts = append(parts, version.String(), suffix)
	}

	return Artifact{
		Name:     name,
		Version:  version,
		FileName: strings.Join(parts, "-"),
	}, nil
}
