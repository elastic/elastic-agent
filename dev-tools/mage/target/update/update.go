// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package update

import (
	"fmt"
	"os"

	"github.com/magefile/mage/mg"

	"github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/dev-tools/mage/target/common"
)

const BeatsModulePath = "github.com/elastic/beats/v7"

func Beats(targetVersion string) error {
	mg.SerialDeps(mg.F(BeatsModule, targetVersion), common.Notice)

	return nil
}

func BeatsModule(targetVersion string) error {
	goArgs := []string{"get", fmt.Sprintf("%s@%s", BeatsModulePath, targetVersion)}

	fmt.Println("Updating beats module in edot package")
	err := mage.Run(nil, os.Stdout, os.Stderr, "go", "internal/edot", goArgs...)
	if err != nil {
		return err
	}

	fmt.Println("Updating beats module in elastic-agent package")
	err = mage.Run(nil, os.Stdout, os.Stderr, "go", "", goArgs...)
	if err != nil {
		return err
	}
	// NOTE: this is not invoked through mg.Deps because
	// we want to always invoke it and guarantee that it runs
	// as mg.Deps does memoization
	return common.Tidy()
}
