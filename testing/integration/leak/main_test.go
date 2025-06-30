// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package leak

import (
	"flag"
	"log"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"

	// import order matters, keep it here
	_ "github.com/elastic/elastic-agent/testing/integration"
)

var flagSet = flag.CommandLine

func init() {
	define.RegisterFlags("integration.", flagSet)
}

func TestMain(m *testing.M) {
	flag.Parse()

	if define.AutoDiscover {
		define.InitAutodiscovery(nil)
	}

	runExitCode := m.Run()

	if define.AutoDiscover {
		discoveredTests, err := define.DumpAutodiscoveryYAML()
		if err != nil {
			log.Fatalf("Error dumping autodiscovery YAML: %v\n", err)
		}

		err = os.WriteFile(define.AutoDiscoveryOutput, discoveredTests, 0644)
		if err != nil {
			log.Fatalf("Error writing autodiscovery data in %q: %v\n", define.AutoDiscoveryOutput, err)
		}
	}

	os.Exit(runExitCode)
}
