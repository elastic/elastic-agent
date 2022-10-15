// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"fmt"
	"os"
	"strings"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/eql"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	// defaultUnitLogLevel is the default log level that a unit will get if one is not defined.
	defaultUnitLogLevel = client.UnitLogLevelInfo
)

var (
	// ErrOutputNotSupported is returned when an input does not support an output type
	ErrOutputNotSupported = newError("input doesn't support output type")
)

// ErrInputRuntimeCheckFail error is used when an input specification runtime prevention check occurs.
type ErrInputRuntimeCheckFail struct {
	// message is the reason defined in the check
	message string
}

// NewErrInputRuntimeCheckFail creates a ErrInputRuntimeCheckFail with the message.
func NewErrInputRuntimeCheckFail(message string) *ErrInputRuntimeCheckFail {
	return &ErrInputRuntimeCheckFail{message}
}

// Error returns the message set on the check.
func (e *ErrInputRuntimeCheckFail) Error() string {
	return e.message
}

// Unit is a single input or output that a component must run.
type Unit struct {
	// ID is the unique ID of the unit.
	ID string `yaml:"id"`

	// Type is the unit type (either input or output).
	Type client.UnitType `yaml:"type"`

	// LogLevel is the unit's log level.
	LogLevel client.UnitLogLevel `yaml:"log_level"`

	// Config is the units expected configuration.
	Config *proto.UnitExpectedConfig `yaml:"config,omitempty"`

	// Err used when the Config cannot be marshalled from its value into a configuration that
	// can actually be sent to a unit. All units with Err set should not be sent to the component.
	Err error `yaml:"error,omitempty"`
}

// Component is a set of units that needs to run.
type Component struct {
	// ID is the unique ID of the component.
	ID string `yaml:"id"`

	// Err used when there is an error with running this input. Used by the runtime to alert
	// the reason that all of these units are failed.
	Err error `yaml:"error,omitempty"`

	// Spec on how the input should run.
	Spec InputRuntimeSpec `yaml:"spec,omitempty"`

	// Units that should be running inside this component.
	Units []Unit `yaml:"units"`
}

// ToComponents returns the components that should be running based on the policy and the current runtime specification.
func (r *RuntimeSpecs) ToComponents(policy map[string]interface{}) ([]Component, error) {
	const revisionKey = "revision"

	outputsMap, err := toIntermediate(policy)
	if err != nil {
		return nil, err
	}
	if outputsMap == nil {
		return nil, nil
	}

	// set the runtime variables that are available in the input specification runtime checks
	hasRoot, err := utils.HasRoot()
	if err != nil {
		return nil, err
	}
	vars, err := transpiler.NewVars(map[string]interface{}{
		"runtime": map[string]interface{}{
			"platform": r.platform.String(),
			"os":       r.platform.OS,
			"arch":     r.platform.Arch,
			"family":   r.platform.Family,
			"major":    r.platform.Major,
			"minor":    r.platform.Minor,
		},
		"user": map[string]interface{}{
			"uid":  os.Geteuid(),
			"gid":  os.Getegid(),
			"root": hasRoot,
		},
	}, nil)
	if err != nil {
		return nil, err
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
			if err == nil {
				// update the inputType to match the spec; as it could have been alias
				inputType = inputSpec.InputType
				if !containsStr(inputSpec.Spec.Outputs, output.outputType) {
					inputSpec = InputRuntimeSpec{} // empty the spec
					err = ErrOutputNotSupported
				} else {
					err = validateRuntimeChecks(&inputSpec.Spec, vars)
					if err != nil {
						inputSpec = InputRuntimeSpec{} // empty the spec
					}
				}
			}
			units := make([]Unit, 0, len(inputs)+1)
			for _, input := range inputs {
				if !input.enabled {
					// skip; not enabled
					continue
				}
				if v, ok := policy[revisionKey]; ok {
					input.input["policy"] = map[string]interface{}{
						revisionKey: v,
					}
				}
				cfg, cfgErr := ExpectedConfig(input.input)
				if cfg != nil {
					cfg.Type = inputType // ensure alias is replaced in the ExpectedConfig to be non-alias type
				}
				units = append(units, Unit{
					ID:       fmt.Sprintf("%s-%s-%s", inputType, outputName, input.id),
					Type:     client.UnitTypeInput,
					LogLevel: input.logLevel,
					Config:   cfg,
					Err:      cfgErr,
				})
			}
			if len(units) > 0 {
				componentID := fmt.Sprintf("%s-%s", inputType, outputName)
				cfg, cfgErr := ExpectedConfig(output.output)
				units = append(units, Unit{
					ID:       componentID,
					Type:     client.UnitTypeOutput,
					LogLevel: output.logLevel,
					Config:   cfg,
					Err:      cfgErr,
				})
				components = append(components, Component{
					ID:    componentID,
					Err:   err,
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
		logLevel, err := getLogLevel(output)
		if err != nil {
			return nil, fmt.Errorf("invalid 'outputs.%s.log_level', %w", name, err)
		}
		outputsMap[name] = outputI{
			name:       name,
			enabled:    enabled,
			logLevel:   logLevel,
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
			// no ID; fallback to type
			idRaw = t
		}
		id, ok := idRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid 'inputs.%d.id', expected a string not a %T", idx, idRaw)
		}
		if hasDuplicate(outputsMap, id) {
			return nil, fmt.Errorf("invalid 'inputs.%d.id', has a duplicate id %q (id is required to be unique)", idx, id)
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
		logLevel, err := getLogLevel(input)
		if err != nil {
			return nil, fmt.Errorf("invalid 'inputs.%d.log_level', %w", idx, err)
		}
		output.inputs[t] = append(output.inputs[t], inputI{
			idx:       idx,
			id:        id,
			enabled:   enabled,
			logLevel:  logLevel,
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
	logLevel  client.UnitLogLevel
	inputType string
	input     map[string]interface{}
}

type outputI struct {
	name       string
	enabled    bool
	logLevel   client.UnitLogLevel
	outputType string
	output     map[string]interface{}
	inputs     map[string][]inputI
}

func validateRuntimeChecks(spec *InputSpec, store eql.VarStore) error {
	for _, prevention := range spec.Runtime.Preventions {
		expression, err := eql.New(prevention.Condition)
		if err != nil {
			// this should not happen because the specification already validates that this
			// should never error; but just in-case we consider this a reason to prevent the running of the input
			return NewErrInputRuntimeCheckFail(err.Error())
		}
		ok, err := expression.Eval(store)
		if err != nil {
			// error is considered a failure and reported as a reason
			return NewErrInputRuntimeCheckFail(err.Error())
		}
		if ok {
			// true means the prevention valid (so input should not run)
			return NewErrInputRuntimeCheckFail(prevention.Message)
		}
	}
	return nil
}

func hasDuplicate(outputsMap map[string]outputI, id string) bool {
	for _, o := range outputsMap {
		for _, i := range o.inputs {
			for _, j := range i {
				if j.id == id {
					return true
				}
			}
		}
	}
	return false
}

func getLogLevel(val map[string]interface{}) (client.UnitLogLevel, error) {
	const logLevelKey = "log_level"

	logLevel := defaultUnitLogLevel
	if logLevelRaw, ok := val[logLevelKey]; ok {
		logLevelStr, ok := logLevelRaw.(string)
		if !ok {
			return defaultUnitLogLevel, fmt.Errorf("expected a string not a %T", logLevelRaw)
		}
		var err error
		logLevel, err = stringToLogLevel(logLevelStr)
		if err != nil {
			return defaultUnitLogLevel, err
		}
		delete(val, logLevelKey)
	}
	return logLevel, nil
}

func stringToLogLevel(val string) (client.UnitLogLevel, error) {
	val = strings.ToLower(strings.TrimSpace(val))
	switch val {
	case "error":
		return client.UnitLogLevelError, nil
	case "warn", "warning":
		return client.UnitLogLevelWarn, nil
	case "info":
		return client.UnitLogLevelInfo, nil
	case "debug":
		return client.UnitLogLevelDebug, nil
	case "trace":
		return client.UnitLogLevelTrace, nil
	}
	return client.UnitLogLevelError, fmt.Errorf("unknown log level type: %s", val)
}
