// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package integration

import (
	"flag"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

var flagSet = flag.CommandLine

func init() {
	define.RegisterFlags("integration.", flagSet)
}

func TestMain(m *testing.M) {
	flag.Parse()
	define.ParseFlags()
	runExitCode := m.Run()

	if define.DryRun {
		// TODO add parsing of requirements and dump them
	}

	os.Exit(runExitCode)
}
