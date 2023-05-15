// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/eql"
)

// InputSpec is the specification for an input type.
type InputSpec struct {
	Name        string      `config:"name" yaml:"name"  validate:"required"`
	Aliases     []string    `config:"aliases,omitempty" yaml:"aliases,omitempty"`
	Description string      `config:"description" yaml:"description" validate:"required"`
	Platforms   []string    `config:"platforms" yaml:"platforms" validate:"required,min=1"`
	Outputs     []string    `config:"outputs,omitempty" yaml:"outputs,omitempty"`
	Shippers    []string    `config:"shippers,omitempty" yaml:"shippers,omitempty"`
	Runtime     RuntimeSpec `config:"runtime,omitempty" yaml:"runtime,omitempty"`

	Command *CommandSpec `config:"command,omitempty" yaml:"command,omitempty"`
	Service *ServiceSpec `config:"service,omitempty" yaml:"service,omitempty"`
}

// Validate ensures correctness of input specification.
func (s *InputSpec) Validate() error {
	if s.Command == nil && s.Service == nil {
		return fmt.Errorf("input '%s' must define either command or service", s.Name)
	}
	for i, a := range s.Platforms {
		if !GlobalPlatforms.Exists(a) {
			return fmt.Errorf("input '%s' defines an unknown platform '%s'", s.Name, a)
		}
		for j, b := range s.Platforms {
			if i != j && a == b {
				return fmt.Errorf("input '%s' defines the platform '%s' more than once", s.Name, a)
			}
		}
	}
	if len(s.Outputs) == 0 && len(s.Shippers) == 0 {
		return fmt.Errorf("input '%s' must define at least one output or one shipper", s.Name)
	}
	for i, a := range s.Outputs {
		for j, b := range s.Outputs {
			if i != j && a == b {
				return fmt.Errorf("input '%s' defines the output '%s' more than once", s.Name, a)
			}
		}
	}
	for i, a := range s.Shippers {
		for j, b := range s.Shippers {
			if i != j && a == b {
				return fmt.Errorf("input '%s' defines the shipper '%s' more than once", s.Name, a)
			}
		}
	}
	for idx, prevention := range s.Runtime.Preventions {
		_, err := eql.New(prevention.Condition)
		if err != nil {
			return fmt.Errorf("input '%s' defined 'runtime.preventions.%d.condition' failed to compile: %w", s.Name, idx, err)
		}
	}
	return nil
}
