// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"fmt"
	"time"
)

// Spec a components specification.
type Spec struct {
	Version int         `config:"version" yaml:"version" validate:"required"`
	Inputs  []InputSpec `config:"inputs,omitempty" yaml:"inputs,omitempty"`
}

// Validate ensures correctness of component specification.
func (s *Spec) Validate() error {
	if s.Version != 2 {
		return errors.New("only version 2 is allowed")
	}
	inputsToPlatforms := make(map[string][]string)
	for i, input := range s.Inputs {
		a, ok := inputsToPlatforms[input.Name]
		if !ok {
			inputsToPlatforms[input.Name] = make([]string, len(input.Platforms))
			copy(inputsToPlatforms[input.Name], input.Platforms)
			continue
		}
		for _, platform := range input.Platforms {
			for _, existing := range a {
				if existing == platform {
					return fmt.Errorf("input %s at inputs.%d defines the same platform as a previous definition", input.Name, i)
				}
			}
			a = append(a, platform)
			inputsToPlatforms[input.Name] = a
		}
	}
	return nil
}

// InputSpec is the specification for an input type.
type InputSpec struct {
	Name        string      `config:"name" yaml:"name"  validate:"required"`
	Aliases     []string    `config:"aliases,omitempty" yaml:"aliases,omitempty"`
	Description string      `config:"description" yaml:"description" validate:"required"`
	Platforms   []string    `config:"platforms" yaml:"platforms" validate:"required,min=1"`
	Outputs     []string    `config:"outputs" yaml:"outputs" validate:"required,min=1"`
	Runtime     RuntimeSpec `config:"runtime" yaml:"runtime"`

	Command *CommandSpec `config:"command,omitempty" yaml:"command,omitempty"`
	Service *ServiceSpec `config:"service,omitempty" yaml:"service,omitempty"`
}

// Validate ensures correctness of input specification.
func (s *InputSpec) Validate() error {
	if s.Command == nil && s.Service == nil {
		return fmt.Errorf("input %s must define either command or service", s.Name)
	}
	for i, a := range s.Platforms {
		for j, b := range s.Platforms {
			if i != j && a == b {
				return fmt.Errorf("input %s defines the platform %s more than once", s.Name, a)
			}
		}
	}
	for i, a := range s.Outputs {
		for j, b := range s.Outputs {
			if i != j && a == b {
				return fmt.Errorf("input %s defines the output %s more than once", s.Name, a)
			}
		}
	}
	return nil
}

// RuntimeSpec is the specification for runtime options.
type RuntimeSpec struct {
	Preventions []RuntimePreventionSpec `config:"preventions" yaml:"preventions"`
}

// RuntimePreventionSpec is the specification that prevents an input to run at execution time.
type RuntimePreventionSpec struct {
	Condition string `config:"condition" yaml:"condition" validate:"required"`
	Message   string `config:"message" yaml:"message" validate:"required"`
}

// CommandSpec is the specification for an input that executes as a subprocess.
type CommandSpec struct {
	Args []string         `config:"args,omitempty" yaml:"args,omitempty"`
	Env  []CommandEnvSpec `config:"env,omitempty" yaml:"env,omitempty"`
}

// CommandEnvSpec is the specification that defines environment variables that will be set to execute the subprocess.
type CommandEnvSpec struct {
	Name  string `config:"name" yaml:"name" validate:"required"`
	Value string `config:"value" yaml:"value" validate:"required"`
}

// ServiceSpec is the specification for an input that executes as a service.
type ServiceSpec struct {
	Operations ServiceOperationsSpec `config:"operations" yaml:"operations" validate:"required"`
}

// ServiceOperationsSpec is the specification of the operations that need to be performed to get a service installed/uninstalled.
type ServiceOperationsSpec struct {
	Check     *ServiceOperationsCommandSpec `config:"check,omitempty" yaml:"check,omitempty"`
	Install   *ServiceOperationsCommandSpec `config:"install" yaml:"install" validate:"required"`
	Uninstall *ServiceOperationsCommandSpec `config:"uninstall" yaml:"uninstall" validate:"required"`
}

// ServiceOperationsCommandSpec is the specification for execution of binaries to perform the check, install, and uninstall.
type ServiceOperationsCommandSpec struct {
	Args    []string         `config:"args,omitempty" yaml:"args,omitempty"`
	Env     []CommandEnvSpec `config:"env,omitempty" yaml:"env,omitempty"`
	Timeout time.Duration    `config:"timeout,omitempty" yaml:"timeout,omitempty"`
}
