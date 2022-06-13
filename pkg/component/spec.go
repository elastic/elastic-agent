// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/program/spec"
)

// Spec a components specification.
type Spec struct {
	Name    string       `yaml:"name,omitempty"`
	Version int          `config:"version" yaml:"version" validate:"required"`
	Inputs  []InputSpec  `config:"inputs,omitempty" yaml:"inputs,omitempty"`
	Outputs []OutputSpec `config:"outputs,omitempty" yaml:"outputs,omitempty"`

	// TODO: For backward comp, removed later
	ProgramSpec *spec.Spec `config:",inline" yaml:",inline"`
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

func (s *Spec) Command() string {
	name := strings.ToLower(s.Name)
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}

	return name
}

func (s *Spec) Args() []string {
	// TODO: once we run input per input:output combination match args to that
	// meaning load args per input set
	if len(s.Inputs) > 0 && s.Inputs[0].Command != nil {
		return s.Inputs[0].Command.Args
	} else if len(s.Outputs) > 0 {
		return s.Outputs[0].Command.Args
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
