// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package update

import (
	"fmt"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/dev-tools/mage/target/common"
)

const BeatsModulePath = "github.com/elastic/beats/v7"

func Beats(targetVersion string) error {
	mg.SerialDeps(mg.F(BeatsModule, targetVersion), common.Notice)

	return nil
}

func BeatsModule(targetVersion string) error {
	goArgs := []string{"get", fmt.Sprintf("%s@%s", BeatsModulePath, targetVersion)}
	err := sh.RunV(mg.GoCmd(), goArgs...)
	if err != nil {
		return err
	}
	return sh.RunV(mg.GoCmd(), "mod", "tidy")
}
