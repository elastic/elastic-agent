// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import "fmt"

// ShipperSpec is the specification for a shipper type.
type ShipperSpec struct {
	Name        string      `config:"name" yaml:"name"  validate:"required"`
	Description string      `config:"description" yaml:"description" validate:"required"`
	Platforms   []string    `config:"platforms" yaml:"platforms" validate:"required,min=1"`
	Outputs     []string    `config:"outputs" yaml:"outputs" validate:"required,min=1"`
	Runtime     RuntimeSpec `config:"runtime,omitempty" yaml:"runtime,omitempty"`

	Command *CommandSpec `config:"command,omitempty" yaml:"command,omitempty"`
}

// Validate ensures correctness of output specification.
func (s *ShipperSpec) Validate() error {
	if s.Command == nil {
		return fmt.Errorf("shipper '%s' must define command (no other type is supported for shippers)", s.Name)
	}
	for i, a := range s.Platforms {
		for j, b := range s.Platforms {
			if i != j && a == b {
				return fmt.Errorf("shipper '%s' defines the platform '%s' more than once", s.Name, a)
			}
		}
	}
	return nil
}
