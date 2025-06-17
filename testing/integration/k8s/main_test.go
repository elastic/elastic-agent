// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"sigs.k8s.io/kustomize/api/filesys"
	"sigs.k8s.io/kustomize/api/krusty"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const agentK8SKustomize = "../../../deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone"

var flagSet = flag.CommandLine

var (
	kustomizeYaml      []byte
	skipKustomizeTests bool
)

func init() {
	define.RegisterFlags("integration.", flagSet)
	flag.BoolVar(&skipKustomizeTests, "integration.k8s.skip-kustomize-tests", false, "Skip kustomize integration tests")
}

func TestMain(m *testing.M) {
	define.SetKubernetesSupported()
	flag.Parse()

	if define.AutoDiscover {
		define.InitAutodiscovery(nil)
	}

	if !define.DryRun {
		ctx := context.Background()
		// prepare tests if not in dry-run mode
		err := initTests(ctx)
		if err != nil {
			log.Fatalf("Error preparing tests: %v\n", err)
		}
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

func initTests(ctx context.Context) error {
	var errs error
	if !skipKustomizeTests {
		if err := renderAgentKustomize(ctx); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

// renderAgentKustomize renders the given kustomize directory to YAML
func renderAgentKustomize(ctx context.Context) error {
	var err error
	kustomizeYaml, err = backoff.Retry(ctx, func() ([]byte, error) {
		// Create a file system pointing to the kustomize directory
		fSys := filesys.MakeFsOnDisk()
		// Create a kustomizer
		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		// Run the kustomizer on the given directory
		resMap, err := k.Run(fSys, agentK8SKustomize)
		if err != nil {
			return nil, fmt.Errorf("error running kustomizer: %w", err)
		}

		// Convert the result to YAML
		renderedManifest, err := resMap.AsYaml()
		if err != nil {
			return nil, fmt.Errorf("error rendering kustomize: %w", err)
		}

		return renderedManifest, nil
	},
		backoff.WithBackOff(backoff.NewConstantBackOff(1*time.Second)),
		backoff.WithMaxTries(10),
	)

	return err
}

func shouldSkipKustomizeTests(t *testing.T) {
	if skipKustomizeTests {
		t.Skip("Skipping kustomize tests because --integration.k8s.skip-kustomize-tests is set.")
	}
}
