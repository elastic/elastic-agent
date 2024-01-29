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

	sets, err := getSets(cmd)
	if err != nil {
		return nil, err
	}

	configFiles = append(configFiles, sets...)
	return configFiles, nil
}

func getSets(cmd *cobra.Command) ([]string, error) {
	var sets []string
	setVals, err := cmd.Flags().GetStringArray(setFlagName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve set flags: %w", err)
	}

	for _, s := range setVals {
		idx := strings.Index(s, "=")
		if idx == -1 {
			// No need for more context, see TestSetFlag/invalid_set.
			return nil, fmt.Errorf("missing equal sign for set value %q", s)
		}
		sets = append(sets, "yaml:"+strings.TrimSpace(strings.ReplaceAll(s[:idx], ".", "::"))+": "+strings.TrimSpace(s[idx+1:]))
	}
	return sets, nil
}
