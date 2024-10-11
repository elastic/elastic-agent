// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/collector/featuregate"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const (
	otelConfigFlagName = "config"
	otelSetFlagName    = "set"
)

func setupOtelFlags(flags *pflag.FlagSet) {
	flags.StringArray(otelConfigFlagName, []string{}, "Locations to the config file(s), note that only a"+
		" single location can be set per flag entry e.g. `--config=file:/path/to/first --config=file:path/to/second`.")

	flags.StringArray(otelSetFlagName, []string{}, "Set arbitrary component config property. The component has to be defined in the config file and the flag"+
		" has a higher precedence. Array config properties are overridden and maps are joined. Example --set=processors.batch.timeout=2s")

	goFlags := new(flag.FlagSet)
	featuregate.GlobalRegistry().RegisterFlags(goFlags)

	flags.AddGoFlagSet(goFlags)
}

func getConfigFiles(cmd *cobra.Command, useDefault bool) ([]string, error) {
	configFiles, err := cmd.Flags().GetStringArray(otelConfigFlagName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve config flags: %w", err)
	}

	if len(configFiles) == 0 {
		if !useDefault {
			return nil, fmt.Errorf("at least one config flag must be provided")
		}
		configFiles = append(configFiles, paths.OtelConfigFile())
	}

	setVals, err := cmd.Flags().GetStringArray(otelSetFlagName)
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
