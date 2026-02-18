// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package update

import (
	"context"
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

<<<<<<< HEAD
func BeatsModule(targetVersion string) error {
	goArgs := []string{"get", fmt.Sprintf("%s@%s", BeatsModulePath, targetVersion)}

	fmt.Println("Updating beats module in edot package")
	err := mage.Run(nil, os.Stdout, os.Stderr, "go", "internal/edot", goArgs...)
=======
func BeatsModule(ctx context.Context, branch string, targetVersion string) error {
	goArgs := []string{"mod", "edit", "-require", fmt.Sprintf("%s@%s", BeatsModulePath, targetVersion)}

	fmt.Printf("Fetching branch '%s' in beats submodule\n", branch)
	err := mage.Run(ctx, nil, os.Stdout, os.Stderr, "git", "beats", "fetch", "origin", branch)
	if err != nil {
		return err
	}

	fmt.Println("Updating beats submodule")
	err = mage.Run(ctx, nil, os.Stdout, os.Stderr, "git", "beats", "checkout", targetVersion)
	if err != nil {
		return err
	}

	fmt.Println("Updating beats module in edot package")
	err = mage.Run(ctx, nil, os.Stdout, os.Stderr, "go", "internal/edot", goArgs...)
>>>>>>> 1a8a5f564 (Refactor mage target configuration (#12128))
	if err != nil {
		return err
	}

	fmt.Println("Updating beats module in elastic-agent package")
	err = mage.Run(ctx, nil, os.Stdout, os.Stderr, "go", "", goArgs...)
	if err != nil {
		return err
	}
	// NOTE: this is not invoked through mg.Deps because
	// we want to always invoke it and guarantee that it runs
	// as mg.Deps does memoization
	return common.Tidy()
}
