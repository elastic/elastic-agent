// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/otel"
)

type componentsOutput struct {
	Receivers []struct {
		Name string `yaml:"name"`
	} `yaml:"receivers"`
	Processors []struct {
		Name string `yaml:"name"`
	} `yaml:"processors"`
	Exporters []struct {
		Name string `yaml:"name"`
	} `yaml:"exporters"`
	Connectors []struct {
		Name string `yaml:"name"`
	} `yaml:"connectors"`
	Extensions []struct {
		Name string `yaml:"name"`
	} `yaml:"extensions"`
}

func TestComponentsCommand(t *testing.T) {

	cmd := &cobra.Command{}
	cmd.SetArgs([]string{"components"})

	expectedOutput, err := os.ReadFile(filepath.Join("testdata", "otel/components-output.yml"))
	require.NoError(t, err)
	expectedComponents := &componentsOutput{}
	err = yaml.Unmarshal(expectedOutput, expectedComponents)
	require.NoError(t, err)

	b := bytes.NewBufferString("")
	cmd.SetOut(b)
	err = otel.Components(cmd)
	require.NoError(t, err)
	outputComponents := &componentsOutput{}
	err = yaml.Unmarshal(b.Bytes(), outputComponents)
	require.NoError(t, err)

	for _, receiver := range expectedComponents.Receivers {
		found := false
		for _, rcvr := range outputComponents.Receivers {
			if receiver.Name == rcvr.Name {
				found = true
				break
			}
		}
		require.Truef(t, found, "receiver not found: %s", receiver.Name)
	}
	for _, exporter := range expectedComponents.Exporters {
		found := false
		for _, exprt := range outputComponents.Exporters {
			if exporter.Name == exprt.Name {
				found = true
				break
			}
		}
		require.Truef(t, found, "exporter not found: %s", exporter.Name)
	}
	for _, processor := range expectedComponents.Processors {
		found := false
		for _, prcsr := range outputComponents.Processors {
			if processor.Name == prcsr.Name {
				found = true
				break
			}
		}
		require.Truef(t, found, "processor not found: %s", processor.Name)
	}
	for _, connector := range expectedComponents.Connectors {
		found := false
		for _, cnctr := range outputComponents.Connectors {
			if connector.Name == cnctr.Name {
				found = true
				break
			}
		}
		require.Truef(t, found, "connector not found: %s", connector.Name)
	}
	for _, extension := range expectedComponents.Extensions {
		found := false
		for _, ext := range outputComponents.Extensions {
			if extension.Name == ext.Name {
				found = true
				break
			}
		}
		require.Truef(t, found, "extension not found: %s", extension.Name)
	}
}
