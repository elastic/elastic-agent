// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import "fmt"

// OutputSpec is the specification for an output type.
type OutputSpec struct {
	Name        string   `config:"name" yaml:"name"  validate:"required"`
	Description string   `config:"description" yaml:"description" validate:"required"`
	Platforms   []string `config:"platforms" yaml:"platforms" validate:"required,min=1"`

	Command *CommandSpec `config:"command,omitempty" yaml:"command,omitempty"`
}

// Validate ensures correctness of output specification.
func (s *OutputSpec) Validate() error {
	if s.Command == nil {
		return fmt.Errorf("input %s must define either command or service", s.Name)
	}
	for i, a := range s.Platforms {
		for j, b := range s.Platforms {
			if i != j && a == b {
				return fmt.Errorf("input %s defines the platform %s more than once", s.Name, a)
			}
		}
	}
	return nil
}
