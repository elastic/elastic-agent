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
