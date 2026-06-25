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

var packageArchMap = map[struct{ os, arch string }]string{
	{"linux", "386"}:     "linux-x86.tar.gz",
	{"linux", "amd64"}:   "linux-x86_64.tar.gz",
	{"linux", "arm64"}:   "linux-arm64.tar.gz",
	{"windows", "386"}:   "windows-x86.zip",
	{"windows", "amd64"}: "windows-x86_64.zip",
	{"windows", "arm64"}: "windows-arm64.zip",
	{"darwin", "amd64"}:  "darwin-x86_64.tar.gz",
	{"darwin", "arm64"}:  "darwin-aarch64.tar.gz",
}

// Artifact provides info for fetching from artifact store.
type Artifact struct {
	Name    string
	FIPS    bool
	OS      string
	Arch    string
	Version *agtversion.ParsedSemVer
}

func New(name string, fips bool, version *agtversion.ParsedSemVer, os, arch string) (Artifact, error) {
	_, found := packageArchMap[struct{ os, arch string }{os, arch}]
	if !found {
		return Artifact{}, errors.New(fmt.Sprintf("'%s/%s' is not a valid combination for a package", os, arch), errors.TypeConfig)
	}

	if version == nil {
		return Artifact{}, errors.New("no version specified for package", errors.TypeConfig)
	}

	return Artifact{Name: name, FIPS: fips, OS: os, Arch: arch, Version: version}, nil
}

func (a *Artifact) FileName() string {
	parts := []string{a.Name}
	if a.FIPS {
		parts = append(parts, "fips")
	}

	suffix := packageArchMap[struct{ os, arch string }{a.OS, a.Arch}] // already checked os/arch in New so should never return no result
	parts = append(parts, a.Version.String(), suffix)

	return strings.Join(parts, "-")
}
