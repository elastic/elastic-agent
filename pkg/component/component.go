// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"fmt"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

// Unit is a single unit that needs to be running inside a component.
type Unit struct {
	ID     string
	Type   client.UnitType
	Config map[string]interface{}
}

// Component is a set of units that needs to run.
type Component struct {
	Spec  InputRuntimeSpec
	Units []Unit
}

// ToComponents returns the components that should be running based on the policy and the current runtime specification.
func (r *RuntimeSpecs) ToComponents(policy map[string]interface{}) ([]Component, error) {
	outputsMap, err := toIntermediate(policy)
	if err != nil {
		return nil, err
	}
	if outputsMap == nil {
		return nil, nil
	}
	var components []Component
	for outputName, output := range outputsMap {
		if !output.enabled {
			// skip; not enabled
			continue
		}

		// merge aliases into same input type
		inputsMap := make(map[string][]inputI)
		for inputType, inputs := range output.inputs {
			realInputType, ok := r.aliasMapping[inputType]
			if ok {
				inputsMap[realInputType] = append(inputsMap[realInputType], inputs...)
			} else {
				inputsMap[inputType] = append(inputsMap[inputType], inputs...)
			}
		}

		for inputType, inputs := range inputsMap {
			inputSpec, err := r.GetInput(inputType)
			if errors.Is(err, ErrNotSupportedOnPlatform) {
				return nil, fmt.Errorf("invalid 'input.%d' type '%s' is not supported on this platform", inputs[0].idx, inputType)
			} else if err != nil {
				return nil, fmt.Errorf("invalid 'input.%d' type '%s' is an unknown input", inputs[0].idx, inputType)
			}
			if !containsStr(inputSpec.Spec.Outputs, output.outputType) {
				return nil, fmt.Errorf("invalid 'input.%d' type '%s' does not support output type '%s'", inputs[0].idx, inputType, output.outputType)
			}
			units := make([]Unit, 0, len(inputs)+1)
			for _, input := range inputs {
				if !input.enabled {
					// skip; not enabled
					continue
				}
				units = append(units, Unit{
					ID:     fmt.Sprintf("%s-%s-%s", inputSpec.InputType, outputName, input.id),
					Type:   client.UnitTypeInput,
					Config: input.input,
				})
			}
			if len(units) > 0 {
				units = append(units, Unit{
					ID:     fmt.Sprintf("%s-%s", inputSpec.InputType, outputName),
					Type:   client.UnitTypeOutput,
					Config: output.output,
				})
				components = append(components, Component{
					Spec:  inputSpec,
					Units: units,
				})
			}
		}
	}
	return components, nil
}

// toIntermediate takes the policy and returns it into an intermediate representation that is easier to map into a set
// of components.
func toIntermediate(policy map[string]interface{}) (map[string]outputI, error) {
	const (
		outputsKey = "outputs"
		enabledKey = "enabled"
		inputsKey  = "inputs"
		typeKey    = "type"
		idKey      = "id"
		useKey     = "use_output"
	)

	// intermediate structure for output to input mapping (this structure allows different input types per output)
	outputsMap := make(map[string]outputI)

	// map the outputs first
	outputsRaw, ok := policy[outputsKey]
	if !ok {
		// no outputs defined; no components then
		return nil, nil
	}
	outputs, ok := outputsRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid 'outputs', expected a map not a %T", outputsRaw)
	}
	for name, outputRaw := range outputs {
		output, ok := outputRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid 'outputs.%s', expected a map not a %T", name, outputRaw)
		}
		typeRaw, ok := output[typeKey]
		if !ok {
			return nil, fmt.Errorf("invalid 'outputs.%s', 'type' missing", name)
		}
		t, ok := typeRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid 'outputs.%s.type', expected a string not a %T", name, typeRaw)
		}
		enabled := true
		if enabledRaw, ok := output[enabledKey]; ok {
			enabledVal, ok := enabledRaw.(bool)
			if !ok {
				return nil, fmt.Errorf("invalid 'outputs.%s.enabled', expected a bool not a %T", name, enabledRaw)
			}
			enabled = enabledVal
			delete(output, enabledKey)
		}
		outputsMap[name] = outputI{
			name:       name,
			enabled:    enabled,
			outputType: t,
			output:     output,
			inputs:     make(map[string][]inputI),
		}
	}

	// map the inputs to the outputs
	inputsRaw, ok := policy[inputsKey]
	if !ok {
		// no inputs; no components then
		return nil, nil
	}
	inputs, ok := inputsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid 'inputs', expected an array not a %T", inputsRaw)
	}
	for idx, inputRaw := range inputs {
		input, ok := inputRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid 'inputs.%d', expected a map not a %T", idx, inputRaw)
		}
		typeRaw, ok := input[typeKey]
		if !ok {
			return nil, fmt.Errorf("invalid 'inputs.%d', 'type' missing", idx)
		}
		t, ok := typeRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid 'inputs.%d.type', expected a string not a %T", idx, typeRaw)
		}
		idRaw, ok := input[idKey]
		if !ok {
			return nil, fmt.Errorf("invalid 'inputs.%d', 'id' missing", idx)
		}
		id, ok := idRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid 'inputs.%d.id', expected a string not a %T", idx, idRaw)
		}
		outputName := "default"
		if outputRaw, ok := input[useKey]; ok {
			outputNameVal, ok := outputRaw.(string)
			if !ok {
				return nil, fmt.Errorf("invalid 'inputs.%d.use_output', expected a string not a %T", idx, outputRaw)
			}
			outputName = outputNameVal
			delete(input, useKey)
		}
		output, ok := outputsMap[outputName]
		if !ok {
			return nil, fmt.Errorf("invalid 'inputs.%d.use_output', references an unknown output '%s'", idx, outputName)
		}
		enabled := true
		if enabledRaw, ok := input[enabledKey]; ok {
			enabledVal, ok := enabledRaw.(bool)
			if !ok {
				return nil, fmt.Errorf("invalid 'inputs.%d.enabled', expected a bool not a %T", idx, enabledRaw)
			}
			enabled = enabledVal
			delete(input, enabledKey)
		}
		output.inputs[t] = append(output.inputs[t], inputI{
			idx:       idx,
			id:        id,
			enabled:   enabled,
			inputType: t,
			input:     input,
		})
	}
	if len(outputsMap) == 0 {
		return nil, nil
	}
	return outputsMap, nil
}

type inputI struct {
	idx       int
	id        string
	enabled   bool
	inputType string
	input     map[string]interface{}
}

type outputI struct {
	name       string
	enabled    bool
	outputType string
	output     map[string]interface{}
	inputs     map[string][]inputI
}
