// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"os"
	"strconv"
)

var ExitCode = "0" // string so it can be set at build time

func main() {
	exitCode, err := strconv.Atoi(ExitCode)
	if err != nil {
		exitCode = -1
	}
	os.Exit(exitCode)
}
