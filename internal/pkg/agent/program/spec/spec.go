// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package spec

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
)

// ErrMissingWhen is returned when no boolean expression is defined for a program.
var ErrMissingWhen = errors.New("program must define a 'When' expression")

// Spec represents a specific program specification, it contains information about how to run the
// program and also the rules to apply to the single configuration to create a specific program
// configuration.
//
// NOTE: Current spec are build at compile time, we want to revisit that to allow other program
// to register their spec in a secure way.
type Spec struct {
	// TODO: For backward comp, removed later
	ServicePort           int                  `config:"service,omitempty" yaml:"service,omitempty"`
	ActionInputTypes      []string             `config:"action_input_types,omitempty" yaml:"action_input_types,omitempty"`
	LogPaths              map[string]string    `config:"log_paths,omitempty" yaml:"log_paths,omitempty"`
	MetricEndpoints       map[string]string    `config:"metric_endpoints,omitempty" yaml:"metric_endpoints,omitempty"`
	Rules                 *transpiler.RuleList `config:"rules" yaml:"rules"`
	CheckInstallSteps     *transpiler.StepList `config:"check_install" yaml:"check_install"`
	PostInstallSteps      *transpiler.StepList `config:"post_install" yaml:"post_install"`
	PreUninstallSteps     *transpiler.StepList `config:"pre_uninstall" yaml:"pre_uninstall"`
	When                  string               `config:"when" yaml:"when"`
	Constraints           string               `config:"constraints" yaml:"constraints"`
	RestartOnOutputChange bool                 `config:"restart_on_output_change,omitempty" yaml:"restart_on_output_change,omitempty"`
	ExportedMetrics       []string             `config:"exported_metrics,omitempty" yaml:"exported_metrics,omitempty"`
}
