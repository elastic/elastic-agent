// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gotool

type goGet func(opts ...ArgOpt) error

// Get runs `go get` and provides optionals for adding command line arguments.
var Get goGet = runGoGet

func runGoGet(opts ...ArgOpt) error {
	args := buildArgs(opts)
	return runVGo("get", args)
}

func (goGet) Download() ArgOpt          { return flagBoolIf("-d", true) }
func (goGet) Update() ArgOpt            { return flagBoolIf("-u", true) }
func (goGet) Package(pkg string) ArgOpt { return posArg(pkg) }
