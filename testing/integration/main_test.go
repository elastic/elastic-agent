// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package integration

import (
	"flag"
	"log"
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

	if define.AutoDiscover {
		define.InitAutodiscovery(nil)
	}

	runExitCode := m.Run()

	if define.AutoDiscover {

		discoveredTests, err := define.DumpAutodiscoveryYAML()
		if err != nil {
			log.Println("Error dumping autodiscovery YAML:", err)
			os.Exit(1)
		}

		err = os.WriteFile(define.AutoDiscoveryOutput, discoveredTests, 0644)
		if err != nil {
			log.Printf("Error writing autodiscovery data in %q: %s", define.AutoDiscoveryOutput, err)
			os.Exit(1)
		}

	}

	os.Exit(runExitCode)
}
