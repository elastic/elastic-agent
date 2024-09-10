// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gotool

import (
	"github.com/magefile/mage/sh"
)

type goLicenser func(opts ...ArgOpt) error

// Licenser runs `go-licenser` and provides optionals for adding command line arguments.
var Licenser goLicenser = runGoLicenser

func runGoLicenser(opts ...ArgOpt) error {
	args := buildArgs(opts).build()
	return sh.RunV("go-licenser", args...)
}

func (goLicenser) Check() ArgOpt                 { return flagBoolIf("-d", true) }
func (goLicenser) License(license string) ArgOpt { return flagArgIf("-license", license) }
func (goLicenser) Exclude(path string) ArgOpt    { return flagArgIf("-exclude", path) }
func (goLicenser) Path(path string) ArgOpt       { return posArg(path) }
