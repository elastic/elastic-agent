// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func getConfigFiles(cmd *cobra.Command) ([]string, error) {
	configFiles, err := cmd.Flags().GetStringArray(configFlagName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve config flags: %w", err)
	}

	if len(configFiles) == 0 {
		configFiles = append(configFiles, paths.OtelConfigFile())
	}

	setVals, err := cmd.Flags().GetStringArray(setFlagName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve set flags: %w", err)
	}

	sets, err := getSets(setVals)
	if err != nil {
		return nil, err
	}

	configFiles = append(configFiles, sets...)
	return configFiles, nil
}

func getSets(setVals []string) ([]string, error) {
	var sets []string
	for _, s := range setVals {
		idx := strings.Index(s, "=")
		if idx == -1 {
			return nil, fmt.Errorf("missing equal sign for set value %q", s)
		}
		sets = append(sets, setToYaml(s, idx))
	}
	return sets, nil
}

func setToYaml(set string, eqIdx int) string {
	if len(set) == 0 {
		return set
	}
	return "yaml:" + strings.TrimSpace(strings.ReplaceAll(set[:eqIdx], ".", "::")) + ": " + strings.TrimSpace(set[eqIdx+1:])
}
