// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func TestOtelFlagsSetup(t *testing.T) {
	fs := new(pflag.FlagSet)
	setupOtelFlags(fs)

	expectedFlags := []string{
		otelConfigFlagName,
		otelSetFlagName,
		"feature-gates",
	}

	for _, expectedFlag := range expectedFlags {
		require.NotNil(t, fs.Lookup(expectedFlag), "Flag %q is not present", expectedFlag)
	}
}

func TestGetConfigFiles(t *testing.T) {
	cmd := newOtelCommandWithArgs(nil, nil)
	configFile := "sample.yaml"
	require.NoError(t, cmd.Flag(otelConfigFlagName).Value.Set(configFile))

	setVal := "set=val"
	sets, err := getSets([]string{setVal})
	require.NoError(t, err)
	require.NoError(t, cmd.Flag(otelSetFlagName).Value.Set(setVal))

	expectedConfigFiles := append([]string{configFile}, sets...)
	configFiles, err := getConfigFiles(cmd, false)
	require.NoError(t, err)
	require.Equal(t, expectedConfigFiles, configFiles)
}

func TestGetConfigFilesWithDefault(t *testing.T) {
	cmd := newOtelCommandWithArgs(nil, nil)

	setVal := "set=val"
	sets, err := getSets([]string{setVal})
	require.NoError(t, err)
	require.NoError(t, cmd.Flag(otelSetFlagName).Value.Set(setVal))

	expectedConfigFiles := append([]string{paths.OtelConfigFile()}, sets...)
	configFiles, err := getConfigFiles(cmd, true)
	require.NoError(t, err)
	require.Equal(t, expectedConfigFiles, configFiles)
}

func TestGetConfigErrorWhenNoConfig(t *testing.T) {
	cmd := newOtelCommandWithArgs(nil, nil)

	_, err := getConfigFiles(cmd, false)
	require.Error(t, err)
}

func TestGetSets(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedSets  []string
		expectedError string
	}{
		{
			name:          "No Set",
			args:          []string{},
			expectedSets:  nil,
			expectedError: "",
		},
		{
			name:          "Valid Set",
			args:          []string{"key=value"},
			expectedSets:  []string{"yaml:key: value"},
			expectedError: "",
		},
		{
			name:          "Valid Multiple Set",
			args:          []string{"key=value", "key2=value2"},
			expectedSets:  []string{"yaml:key: value", "yaml:key2: value2"},
			expectedError: "",
		},
		{
			name:          "Invalid Set",
			args:          []string{"keyvalue"},
			expectedSets:  nil,
			expectedError: "missing equal sign for set value \"keyvalue\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sets, err := getSets(tc.args)
			if len(tc.expectedError) > 0 {
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.expectedSets, sets)
		})
	}
}

func TestSetToYaml(t *testing.T) {
	testCases := []struct {
		name        string
		set         string
		idx         int
		expectedSet string
	}{
		{
			name:        "Empty set",
			set:         "",
			idx:         0,
			expectedSet: "",
		},
		{
			name:        "Simple set",
			set:         "key=value",
			idx:         3,
			expectedSet: "yaml:key: value",
		},
		{
			name:        "Dotted key",
			set:         "key.subkey=value",
			idx:         10,
			expectedSet: "yaml:key::subkey: value",
		},
		{
			name:        "Dotted value",
			set:         "key=value.somethingelse",
			idx:         3,
			expectedSet: "yaml:key: value.somethingelse",
		},
	}

	for _, tc := range testCases {
		actualSet := setToYaml(tc.set, tc.idx)
		assert.Equal(t, tc.expectedSet, actualSet)
	}
}
