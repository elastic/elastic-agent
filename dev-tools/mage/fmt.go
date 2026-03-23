// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
)

var (
	// GoImportsImportPath controls the import path used to install goimports.
	GoImportsImportPath = "golang.org/x/tools/cmd/goimports"

	// GoImportsLocalPrefix is a string prefix matching imports that should be
	// grouped after third-party packages.
	GoImportsLocalPrefix = "github.com/elastic"
)

// Format adds license headers, formats .go files with goimports, and formats
// .py files with autopep8.
func Format(ctx context.Context) error {
	cfg := SettingsFromContext(ctx)
	// Don't run AddLicenseHeaders and GoImports concurrently because they
	// both can modify the same files.
	if BeatProjectType != CommunityProject {
		if err := AddLicenseHeaders(cfg); err != nil {
			return err
		}
	}
	return GoImports()
}

// GoImports executes goimports against all .go files in and below the CWD.
func GoImports() error {
	goFiles, err := FindFilesRecursive(func(path string, _ os.FileInfo) bool {
		return filepath.Ext(path) == ".go"
	})
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return nil
	}

	fmt.Println(">> fmt - goimports: Formatting Go code")
	if err := gotool.Install(
		gotool.Install.Package(filepath.Join(GoImportsImportPath)),
	); err != nil {
		return err
	}

	args := append(
		[]string{"-local", GoImportsLocalPrefix, "-l", "-w"},
		goFiles...,
	)

	return sh.RunV("goimports", args...)
}

// AddLicenseHeaders adds license headers to .go files. It applies the
// appropriate license header based on the value of devtools.BeatLicense.
func AddLicenseHeaders(cfg *Settings) error {
	if cfg.Fmt.CheckHeadersDisabled {
		return nil
	}

	fmt.Println(">> fmt - go-licenser: Adding missing headers")

	mg.Deps(InstallGoLicenser)

	var license string
	switch cfg.Beat.License {
	case "Elasticv2", "Elastic License 2.0":
		license = "Elasticv2"
	default:
		return fmt.Errorf("unknown license type %s", cfg.Beat.License)
	}

	licenser := gotool.Licenser
	return licenser(licenser.License(license), licenser.Exclude("beats"))
}
