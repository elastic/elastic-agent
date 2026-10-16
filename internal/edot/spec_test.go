// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSpecIncludesSyntheticsAPIInput(t *testing.T) {
	specData, err := os.ReadFile("spec.yml")
	require.NoError(t, err)

	var spec struct {
		Inputs []struct {
			Name string `yaml:"name"`
		} `yaml:"inputs"`
	}
	require.NoError(t, yaml.Unmarshal(specData, &spec))

	for _, input := range spec.Inputs {
		if input.Name == "synthetics/api" {
			return
		}
	}

	t.Fatal("spec.yml must register the synthetics/api input")
}

// A Beat receiver is a full Beat, so one receiver per monitor makes memory grow
// with the monitor count. Every synthetics input runs all monitors of a
// component in one receiver.
func TestSpecSyntheticsSingleReceiver(t *testing.T) {
	specData, err := os.ReadFile("spec.yml")
	require.NoError(t, err)

	var spec struct {
		Inputs []struct {
			Name           string `yaml:"name"`
			SingleReceiver bool   `yaml:"single_receiver"`
		} `yaml:"inputs"`
	}
	require.NoError(t, yaml.Unmarshal(specData, &spec))

	want := map[string]bool{
		"synthetics/http":    true,
		"synthetics/icmp":    true,
		"synthetics/tcp":     true,
		"synthetics/api":     true,
		"synthetics/browser": true,
	}
	found := map[string]bool{}
	for _, input := range spec.Inputs {
		expected, ok := want[input.Name]
		if !ok {
			continue
		}
		found[input.Name] = true
		require.Equalf(t, expected, input.SingleReceiver, "single_receiver for %s", input.Name)
	}
	require.Len(t, found, len(want), "spec.yml must register every synthetics input")
}
