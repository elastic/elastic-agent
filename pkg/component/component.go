// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

type ComponentType int

const (
	INPUT ComponentType = iota + 1
	OUTPUT
	FLEET_SERVER
)

type Component struct {
	Type ComponentType
	Name string
	Spec Spec
}

// HandlesOutput returns true if DPU is responsible for specified output.
func (dpu *Component) HandlesOutput(output string) bool {
	for _, pt := range dpu.Spec.Outputs {
		if !compareType(output, pt.Name) {
			continue
		}

		if matchesArch(pt.Platforms) {
			// TODO: optimalization, load only relevant inputs for current arch
			return true
		}
	}

	return false
}

// HandlesInput returns true if DPU is responsible for specified input.
func (dpu *Component) HandlesInput(input string, output string) bool {
	for _, pt := range dpu.Spec.Inputs {
		if !compareType(input, pt.Name, pt.Aliases...) {
			continue
		}

		if !matchesArch(pt.Platforms) {
			// TODO: optimalization, load only relevant inputs for current arch
			continue
		}

		for _, out := range pt.Outputs {
			if compareType(output, out) {
				return true
			}
		}
	}

	return false
}

// HandlesInputs returns subset of processingTypes provided which DPU is responsible for.
func (dpu *Component) HandlesInputs(inputs []string, output string) []string {
	handled := make([]string, 0, len(inputs))
	for _, pt := range inputs {
		if dpu.HandlesInput(pt, output) {
			handled = append(handled, pt)
		}
	}

	return handled
}

// Command creates a command with args to be executed.
func (dpu *Component) Command() (string, []string) {
	return "", nil
}

func matchesArch(requiredArchs []string) bool {
	// TODO: implement
	return true
}

func compareType(required, mainType string, aliases ...string) bool {
	// TODO: support wildcards
	if required == mainType {
		return true
	}

	for _, h := range aliases {
		if h == required {
			return true
		}
	}
	return false
}
