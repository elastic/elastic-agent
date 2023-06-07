// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/eql"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// GenerateMonitoringCfgFn is a function that can inject information into the model generation process.
type GenerateMonitoringCfgFn func(map[string]interface{}, []Component, map[string]string) (map[string]interface{}, error)

type HeadersProvider interface {
	Headers() map[string]string
}

const (
	// defaultUnitLogLevel is the default log level that a unit will get if one is not defined.
	defaultUnitLogLevel = client.UnitLogLevelInfo
	headersKey          = "headers"
	elasticsearchType   = "elasticsearch"
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

// ShipperReference provides a reference to the shipper component/unit that a component is connected to.
type ShipperReference struct {
	// ComponentID is the ID of the component that this component is connected to.
	ComponentID string `yaml:"component_id"`

	// UnitID is the ID of the unit inside the component that this component is connected to.
	UnitID string `yaml:"unit_id"`
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

// Signed Strongly typed configuration for the signed data
type Signed struct {
	Data      string `yaml:"data"`
	Signature string `yaml:"signature"`
}

// IsSigned Checks if the signature exists, safe to call on nil
func (s *Signed) IsSigned() bool {
	return (s != nil && (len(s.Signature) > 0))
}

// ErrNotFound is returned if the expected "signed" property itself or it's expected properties are missing or not a valid data type
var ErrNotFound = errors.New("not found")

// SignedFromPolicy Returns Signed instance from the nested map representation of the agent configuration
func SignedFromPolicy(policy map[string]interface{}) (*Signed, error) {
	v, ok := policy["signed"]
	if !ok {
		return nil, fmt.Errorf("policy is not signed: %w", ErrNotFound)
	}

	signed, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("policy \"signed\" is not map: %w", ErrNotFound)
	}

	data, err := getStringValue(signed, "data")
	if err != nil {
		return nil, err
	}

	signature, err := getStringValue(signed, "signature")
	if err != nil {
		return nil, err
	}

	res := &Signed{
		Data:      data,
		Signature: signature,
	}
	return res, nil
}

func getStringValue(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing signed \"%s\": %w", key, ErrNotFound)
	}

	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("signed \"%s\" is not string: %w", key, ErrNotFound)
	}

	return s, nil
}

// Component is a set of units that needs to run.
type Component struct {
	// ID is the unique ID of the component.
	ID string `yaml:"id"`

	// Err used when there is an error with running this input. Used by the runtime to alert
	// the reason that all of these units are failed.
	Err error `yaml:"error,omitempty"`

	// InputSpec on how the input should run. (not set when ShipperSpec set)
	InputSpec *InputRuntimeSpec `yaml:"input_spec,omitempty"`

	// ShipperSpec on how the shipper should run. (not set when InputSpec set)
	ShipperSpec *ShipperRuntimeSpec `yaml:"shipper_spec,omitempty"`

	// Units that should be running inside this component.
	Units []Unit `yaml:"units"`

	// Features configuration the component should use.
	Features *proto.Features `yaml:"features,omitempty"`

	// Shipper references the component/unit that this component used as its output. (not set when ShipperSpec)
	Shipper *ShipperReference `yaml:"shipper,omitempty"`
}

// Type returns the type of the component.
func (c *Component) Type() string {
	if c.InputSpec != nil {
		return c.InputSpec.InputType
	} else if c.ShipperSpec != nil {
		return c.ShipperSpec.ShipperType
	}
	return ""
}

// Model components model
type Model struct {
	Components []Component `yaml:"components,omitempty"`
	Signed     *Signed     `yaml:"signed,omitempty"`
}

// ToComponents returns the components that should be running based on the policy and
// the current runtime specification.
func (r *RuntimeSpecs) ToComponents(
	policy map[string]interface{},
	monitoringInjector GenerateMonitoringCfgFn,
	ll logp.Level,
	headers HeadersProvider,
) ([]Component, error) {
	components, binaryMapping, err := r.PolicyToComponents(policy, ll, headers)
	if err != nil {
		return nil, err
	}

	if monitoringInjector != nil {
		monitoringCfg, err := monitoringInjector(policy, components, binaryMapping)
		if err != nil {
			return nil, fmt.Errorf("failed to inject monitoring: %w", err)
		}

		if monitoringCfg != nil {
			// monitoring is enabled
			monitoringComps, _, err := r.PolicyToComponents(monitoringCfg, ll, headers)
			if err != nil {
				return nil, fmt.Errorf("failed to generate monitoring components: %w", err)
			}

			components = append(components, monitoringComps...)
		}
	}

	return components, nil
}

// varsForPlatform sets the runtime variables that are available in the
// input specification runtime checks. This function should always be
// edited in sync with the documentation in specs/README.md.
func varsForPlatform(platform PlatformDetail) (*transpiler.Vars, error) {
	hasRoot, err := utils.HasRoot()
	if err != nil {
		return nil, err
	}
	return transpiler.NewVars("", map[string]interface{}{
		"runtime": map[string]interface{}{
			"platform": platform.String(),
			"os":       platform.OS,
			"arch":     platform.Arch,
			"family":   platform.Family,
			"major":    platform.Major,
			"minor":    platform.Minor,
		},
		"user": map[string]interface{}{
			"root": hasRoot,
		},
	}, nil)
}

// PolicyToComponents takes the policy and generated a component model along with providing
// a mapping between component and the running binary.
func (r *RuntimeSpecs) PolicyToComponents(
	policy map[string]interface{},
	ll logp.Level,
	headers HeadersProvider,
) ([]Component, map[string]string, error) {
	// get feature flags from policy
	featureFlags, err := features.Parse(policy)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse feature flags from policy: %w", err)
	}

	outputsMap, err := toIntermediate(policy, r.aliasMapping, ll, headers)
	if err != nil {
		return nil, nil, err
	}
	if outputsMap == nil {
		return nil, nil, nil
	}

	vars, err := varsForPlatform(r.platform)
	if err != nil {
		return nil, nil, err
	}

	// order output keys; ensures result is always the same order
	outputKeys := make([]string, 0, len(outputsMap))
	for k := range outputsMap {
		outputKeys = append(outputKeys, k)
	}
	sort.Strings(outputKeys)

	var components []Component
	componentIdsInputMap := make(map[string]string)
	for _, outputName := range outputKeys {
		output := outputsMap[outputName]
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

		shipperMap := make(map[string][]string)
		for inputType, inputs := range inputsMap {
			var supportedShipper ShipperRuntimeSpec
			var usingShipper bool

			inputSpec, err := r.GetInput(inputType)
			if err == nil {
				// update the inputType to match the spec; as it could have been alias
				inputType = inputSpec.InputType

				// determine if we are operating with shipper support
				supportedShipper, usingShipper = getSupportedShipper(r, output, inputSpec, vars)
				if !usingShipper {
					if !containsStr(inputSpec.Spec.Outputs, output.outputType) {
						inputSpec = InputRuntimeSpec{} // empty the spec
						err = ErrOutputNotSupported
					} else {
						err = validateRuntimeChecks(&inputSpec.Spec.Runtime, vars)
						if err != nil {
							inputSpec = InputRuntimeSpec{} // empty the spec
						}
					}
				}
			}
			units := make([]Unit, 0, len(inputs)+1)
			for _, input := range inputs {
				if !input.enabled {
					// skip; not enabled
					continue
				}

				// Inject the top level fleet policy revision into each into configuration. This
				// allows individual inputs (like endpoint) to detect policy changes more easily.
				injectInputPolicyID(policy, input.input)

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
				if usingShipper {
					// using shipper for this component
					connected := shipperMap[supportedShipper.ShipperType]
					connected = append(connected, componentID)
					shipperMap[supportedShipper.ShipperType] = connected
				} else {
					// using output inside the component
					cfg, cfgErr := ExpectedConfig(output.output)
					units = append(units, Unit{
						ID:       componentID,
						Type:     client.UnitTypeOutput,
						LogLevel: output.logLevel,
						Config:   cfg,
						Err:      cfgErr,
					})
				}

				components = append(components, Component{
					ID:        componentID,
					Err:       err,
					InputSpec: &inputSpec,
					Units:     units,
					Features:  featureFlags.AsProto(),
				})
				componentIdsInputMap[componentID] = inputSpec.BinaryName
			}
		}

		// create the shipper components and units
		for shipperType, connected := range shipperMap {
			shipperSpec, _ := r.GetShipper(shipperType) // type always exists at this point
			shipperCompID := fmt.Sprintf("%s-%s", shipperType, outputName)

			var shipperUnits []Unit
			for _, componentID := range connected {
				for i, component := range components {
					if component.ID == componentID && component.Err == nil {
						cfg, cfgErr := componentToShipperConfig(shipperType, component)
						shipperUnit := Unit{
							ID:       componentID,
							Type:     client.UnitTypeInput,
							LogLevel: output.logLevel,
							Config:   cfg,
							Err:      cfgErr,
						}
						shipperUnits = append(shipperUnits, shipperUnit)
						component.Shipper = &ShipperReference{
							ComponentID: shipperCompID,
							UnitID:      shipperUnit.ID,
						}
						cfg, cfgErr = ExpectedConfig(map[string]interface{}{
							"type": shipperType,
						})
						component.Units = append(component.Units, Unit{
							ID:       componentID,
							Type:     client.UnitTypeOutput,
							LogLevel: output.logLevel,
							Config:   cfg,
							Err:      cfgErr,
						})
						component.Features = featureFlags.AsProto()

						components[i] = component
						break
					}
				}
			}

			if len(shipperUnits) > 0 {
				cfg, cfgErr := ExpectedConfig(output.output)
				shipperUnits = append(shipperUnits, Unit{
					ID:       shipperCompID,
					Type:     client.UnitTypeOutput,
					LogLevel: output.logLevel,
					Config:   cfg,
					Err:      cfgErr,
				})
				components = append(components, Component{
					ID:          shipperCompID,
					ShipperSpec: &shipperSpec,
					Units:       shipperUnits,
					Features:    featureFlags.AsProto(),
				})
			}
		}
	}

	return components, componentIdsInputMap, nil
}

// Injects or creates a policy.revision sub-object in the input map.
func injectInputPolicyID(fleetPolicy map[string]interface{}, input map[string]interface{}) {
	if input == nil {
		return
	}

	// If there is no top level fleet policy revision, there's nothing to inject.
	revision, exists := fleetPolicy["revision"]
	if !exists {
		return
	}

	// Check if a policy key exists with a non-nil policy object.
	policyObj, exists := input["policy"]
	if exists && policyObj != nil {
		// If the policy object converts to map[string]interface{}, inject the revision key.
		// Note that if the interface conversion here fails, we do nothing because we don't
		// know what type of object exists with the policy key.
		if policyMap, ok := policyObj.(map[string]interface{}); ok {
			policyMap["revision"] = revision
		}
	} else {
		// If there was no policy key or the value was nil, then inject a policy object with a revision key.
		input["policy"] = map[string]interface{}{
			"revision": revision,
		}
	}
}

func componentToShipperConfig(shipperType string, comp Component) (*proto.UnitExpectedConfig, error) {
	cfgUnits := make([]interface{}, 0, len(comp.Units))
	for _, unit := range comp.Units {
		if unit.Err == nil && unit.Type == client.UnitTypeInput {
			cfgUnits = append(cfgUnits, map[string]interface{}{
				"id":     unit.ID,
				"config": unit.Config.Source.AsMap(),
			})
		}
	}
	cfg := map[string]interface{}{
		"id":    comp.ID,
		"type":  shipperType,
		"units": cfgUnits,
	}
	return ExpectedConfig(cfg)
}

func getSupportedShipper(r *RuntimeSpecs, output outputI, inputSpec InputRuntimeSpec, vars eql.VarStore) (ShipperRuntimeSpec, bool) {
	const (
		enabledKey = "enabled"
	)

	shippers, err := r.GetShippers(output.outputType)
	if err != nil {
		return ShipperRuntimeSpec{}, false
	}
	supportedShippers := make([]ShipperRuntimeSpec, 0, len(shippers))
	for _, shipper := range shippers {
		if containsStr(inputSpec.Spec.Shippers, shipper.ShipperType) {
			// validate the runtime specification to determine if it can even run
			err = validateRuntimeChecks(&shipper.Spec.Runtime, vars)
			if err != nil {
				// shipper cannot run
				continue
			}
			// beta-mode the shipper is not on by default, so we need to ensure that this shipper type
			// is enabled in the output configuration
			shipperConfigRaw, ok := output.output[shipper.ShipperType]
			if ok {
				// key exists enabled by default unless explicitly disabled
				enabled := true
				if shipperConfig, ok := shipperConfigRaw.(map[string]interface{}); ok {
					if enabledRaw, ok := shipperConfig[enabledKey]; ok {
						if enabledVal, ok := enabledRaw.(bool); ok {
							enabled = enabledVal
						}
					}
				}
				if enabled {
					// inputs supports this shipper (and it's enabled)
					supportedShippers = append(supportedShippers, shipper)
				}
			}
		}
	}
	if len(supportedShippers) == 0 {
		return ShipperRuntimeSpec{}, false
	}
	// in the case of multiple shippers the first is taken from the input specification (this allows an input to
	// prefer another shipper over a different shipper)
	return supportedShippers[0], true
}

// toIntermediate takes the policy and returns it into an intermediate representation that is easier to map into a set
// of components.
func toIntermediate(policy map[string]interface{}, aliasMapping map[string]string, ll logp.Level, headers HeadersProvider) (map[string]outputI, error) {
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
		logLevel, err := getLogLevel(output, ll)
		if err != nil {
			return nil, fmt.Errorf("invalid 'outputs.%s.log_level', %w", name, err)
		}

		// inject headers configured during enroll
		if t == elasticsearchType && headers != nil {
			// can be nil when called from install/uninstall
			if agentHeaders := headers.Headers(); len(agentHeaders) > 0 {
				headers := make(map[string]interface{})
				if existingHeadersRaw, found := output[headersKey]; found {
					existingHeaders, ok := existingHeadersRaw.(map[string]interface{})
					if !ok {
						return nil, fmt.Errorf("invalid 'outputs.headers', expected a map not a %T", outputRaw)
					}
					headers = existingHeaders
				}

				for headerName, headerVal := range agentHeaders {
					headers[headerName] = headerVal
				}

				output[headersKey] = headers
			}
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
		if realInputType, found := aliasMapping[t]; found {
			t = realInputType
			// by replacing type we make sure component understands aliasing
			input[typeKey] = t
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
			return nil, fmt.Errorf("invalid 'inputs.%d.id', has a duplicate id %q. Please add a unique value for the 'id' key to each input in the agent policy", idx, id)
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
		logLevel, err := getLogLevel(input, ll)
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

func validateRuntimeChecks(runtime *RuntimeSpec, store eql.VarStore) error {
	for _, prevention := range runtime.Preventions {
		expression, err := eql.New(prevention.Condition)
		if err != nil {
			// this should not happen because the specification already validates that this
			// should never error; but just in-case we consider this a reason to prevent the running of the input
			return NewErrInputRuntimeCheckFail(err.Error())
		}
		ok, err := expression.Eval(store, false)
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

func getLogLevel(val map[string]interface{}, ll logp.Level) (client.UnitLogLevel, error) {
	const logLevelKey = "log_level"

	logLevel, err := stringToLogLevel(ll.String())
	if err != nil {
		return defaultUnitLogLevel, err
	}
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
