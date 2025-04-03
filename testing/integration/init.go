// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package integration

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// FIXME: this code should be removed once https://github.com/elastic/kibana/issues/213337
// is resolved.
var (
	// preinstalledPackages is a map of packages that are pre-installed by the
	// integration tests runner before any integration tests are executed. This is
	// to prevent multiple concurrent tests from trying to install the same package
	// and causing a conflict.
	preinstalledPackages map[string]string

	//go:embed testdata/preinstalled_packages.json
	preinstalledPackagesJSON []byte
)

func init() {
	err := initializePreinstalledPackages()
	if err != nil {
		panic("unable to parse list of preinstalled packages: " + err.Error())
	}
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func initializePreinstalledPackages() error {
	var packages struct {
		Packages []Package `json:"packages"`
	}

	err := json.Unmarshal(preinstalledPackagesJSON, &packages)
	if err != nil {
		return fmt.Errorf("unable to parse preinstalled packages JSON: %w", err)
	}

	preinstalledPackages = make(map[string]string, len(packages.Packages))
	for _, pkg := range packages.Packages {
		preinstalledPackages[pkg.Name] = pkg.Version
	}

	return nil
}
