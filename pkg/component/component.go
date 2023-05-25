// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
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

// ShipperReference identifies a connection from a source component to
// a shipper.
type ShipperReference struct {
	// ShipperType is the type of shipper being connected to.
	ShipperType string `yaml:"shipper_type"`

	// ComponentID is the component ID of the shipper being connected to.
	ComponentID string `yaml:"component_id"`

	// UnitID is the ID inside the shipper of the input unit corresponding to this connection.
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

	// ShipperRef references the component/unit that this component used as its output. (not set when ShipperSpec)
	ShipperRef *ShipperReference `yaml:"shipper,omitempty"`
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

func unitForInput(input inputI, id string) Unit {
	cfg, cfgErr := ExpectedConfig(input.config)
	return Unit{
		ID:       id,
		Type:     client.UnitTypeInput,
		LogLevel: input.logLevel,
		Config:   cfg,
		Err:      cfgErr,
	}
}

func unitForOutput(output outputI, id string) Unit {
	cfg, cfgErr := ExpectedConfig(output.config)
	return Unit{
		ID:       id,
		Type:     client.UnitTypeOutput,
		LogLevel: output.logLevel,
		Config:   cfg,
		Err:      cfgErr,
	}
}

func unitForShipperOutput(output outputI, id string, shipperType string) Unit {
	cfg, cfgErr := ExpectedConfig(map[string]interface{}{
		"type": shipperType,
	})
	return Unit{
		ID:       id,
		Type:     client.UnitTypeOutput,
		LogLevel: output.logLevel,
		Config:   cfg,
		Err:      cfgErr,
	}
}

// Collect all inputs of a particular type going to a particular
// output into a Component. The returned Component may have no
// units if no valid inputs were found.
func (r *RuntimeSpecs) componentForInputType(
	inputType string,
	output outputI,
	featureFlags *features.Flags,
) Component {
	componentID := fmt.Sprintf("%s-%s", inputType, output.name)

	inputSpec, componentErr := r.GetInput(inputType)
	var shipperType string
	var shipperRef *ShipperReference
	if componentErr == nil {
		if output.useShipper {
			shipperType, componentErr =
				r.getSupportedShipperType(inputSpec, output.outputType)

			if componentErr == nil {
				// We've found a valid shipper, construct the reference
				shipperRef = &ShipperReference{
					ShipperType: shipperType,
					ComponentID: fmt.Sprintf("%s-%s", shipperType, output.name),
					// The unit ID of this connection in the shipper is the same as the
					// input's component id.
					UnitID: componentID,
				}
			}
		} else if !containsStr(inputSpec.Spec.Outputs, output.outputType) {
			// We aren't using the shipper, and this output type isn't in the
			// input spec's supported list.
			componentErr = ErrOutputNotSupported
		}
	}
	// If there's an error at this point we still proceed with assembling the
	// policy into a component, we just attach the error to its Err field to
	// indicate that it can't be run.

	var units []Unit
	for _, input := range output.inputs[inputType] {
		if input.enabled {
			unitID := fmt.Sprintf("%s-%s", componentID, input.id)
			units = append(units, unitForInput(input, unitID))
		}
	}
	if len(units) > 0 {
		if output.useShipper {
			// Shipper units are skipped if componentErr isn't nil, because in that
			// case we generally don't have a valid shipper type to base it on.
			if componentErr == nil {
				units = append(units,
					unitForShipperOutput(output, componentID, shipperType))
			}
		} else {
			units = append(units, unitForOutput(output, componentID))
		}
	}
	return Component{
		ID:         componentID,
		Err:        componentErr,
		InputSpec:  &inputSpec,
		Units:      units,
		Features:   featureFlags.AsProto(),
		ShipperRef: shipperRef,
	}
}

func (r *RuntimeSpecs) componentsForOutput(output outputI, featureFlags *features.Flags) []Component {
	var components []Component
	shipperTypes := make(map[string]bool)
	for inputType := range output.inputs {
		// No need for error checking at this stage -- we are guaranteed
		// to get a Component back. If there is an error that prevents it
		// from running then it will be in the Component's Err field and
		// we will report it later. The only thing we skip is a component
		// with no units.
		component := r.componentForInputType(inputType, output, featureFlags)
		if len(component.Units) > 0 {
			if component.ShipperRef != nil {
				// If this component uses a shipper, mark that shipper type as active
				shipperTypes[component.ShipperRef.ShipperType] = true
			}
			components = append(components, component)
		}
	}

	// create the shipper components to go with the inputs
	for shipperType := range shipperTypes {
		shipperComponent, ok :=
			r.componentForShipper(shipperType, output, components, featureFlags)
		if ok {
			components = append(components, shipperComponent)
		}
	}
	return components
}

func (r *RuntimeSpecs) componentForShipper(
	shipperType string,
	output outputI,
	inputComponents []Component,
	featureFlags *features.Flags,
) (Component, bool) {

	shipperSpec := r.shipperSpecs[shipperType] // type always exists at this point
	shipperCompID := fmt.Sprintf("%s-%s", shipperType, output.name)

	var shipperUnits []Unit
	for _, component := range inputComponents {
		if component.Err != nil {
			continue
		}
		if component.ShipperRef == nil || component.ShipperRef.ShipperType != shipperType {
			continue
		}
		cfg, cfgErr := componentToShipperConfig(shipperType, component)
		shipperUnit := Unit{
			ID:       component.ID,
			Type:     client.UnitTypeInput,
			LogLevel: output.logLevel,
			Config:   cfg,
			Err:      cfgErr,
		}
		shipperUnits = append(shipperUnits, shipperUnit)

	}

	if len(shipperUnits) > 0 {
		cfg, cfgErr := ExpectedConfig(output.config)
		shipperUnits = append(shipperUnits, Unit{
			ID:       shipperCompID,
			Type:     client.UnitTypeOutput,
			LogLevel: output.logLevel,
			Config:   cfg,
			Err:      cfgErr,
		})
		return Component{
			ID:          shipperCompID,
			ShipperSpec: &shipperSpec,
			Units:       shipperUnits,
			Features:    featureFlags.AsProto(),
		}, true
	}
	return Component{}, false
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

	// order output keys; ensures result is always the same order
	outputKeys := make([]string, 0, len(outputsMap))
	for k := range outputsMap {
		outputKeys = append(outputKeys, k)
	}
	sort.Strings(outputKeys)

	var components []Component
	for _, outputName := range outputKeys {
		output := outputsMap[outputName]
		if output.enabled {
			components = append(components,
				r.componentsForOutput(output, featureFlags)...)
		}
	}

	componentIdsInputMap := make(map[string]string)
	for _, component := range components {
		if spec := component.InputSpec; spec != nil {
			componentIdsInputMap[component.ID] = spec.BinaryName
		}
	}

	return components, componentIdsInputMap, nil
}

// Injects or creates a policy.revision sub-object in the input map.
func injectInputPolicyID(fleetPolicy map[string]interface{}, inputConfig map[string]interface{}) {
	if inputConfig == nil {
		return
	}

	// If there is no top level fleet policy revision, there's nothing to inject.
	revision, exists := fleetPolicy["revision"]
	if !exists {
		return
	}

	// Check if a policy key exists with a non-nil policy object.
	if policyObj := inputConfig["policy"]; policyObj != nil {
		// If the policy object converts to map[string]interface{}, inject the revision key.
		// Note that if the interface conversion here fails, we do nothing because we don't
		// know what type of object exists with the policy key.
		if policyMap, ok := policyObj.(map[string]interface{}); ok {
			policyMap["revision"] = revision
		}
	} else {
		// If there was no policy key or the value was nil, then inject a policy object with a revision key.
		inputConfig["policy"] = map[string]interface{}{
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

// Scan the list of shippers looking for one that supports the given
// input spec and output type. If one is found, return its type,
// otherwise return an error.
func (r *RuntimeSpecs) getSupportedShipperType(
	inputSpec InputRuntimeSpec,
	outputType string,
) (string, error) {
	shippersForOutput := r.shipperOutputs[outputType]
	// Traverse in the order given by the input spec. This lets inputs specify
	// a preferred order if there is more than one option.
	for _, name := range inputSpec.Spec.Shippers {
		if !containsStr(shippersForOutput, name) {
			continue
		}
		shipper, ok := r.shipperSpecs[name]
		if !ok {
			continue
		}
		// make sure the runtime checks for this shipper pass
		err := validateRuntimeChecks(&shipper.Spec.Runtime, r.platform)
		if err != nil {
			continue
		}

		return shipper.ShipperType, nil
	}
	return "", ErrOutputNotSupported
}

// toIntermediate takes the policy and returns it into an intermediate representation that is easier to map into a set
// of components.
func toIntermediate(policy map[string]interface{}, aliasMapping map[string]string, ll logp.Level, headers HeadersProvider) (map[string]outputI, error) {
	const (
		outputsKey    = "outputs"
		enabledKey    = "enabled"
		inputsKey     = "inputs"
		typeKey       = "type"
		idKey         = "id"
		useOutputKey  = "use_output"
		useShipperKey = "use_shipper"
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
		useShipper := false
		if useShipperRaw, ok := output[useShipperKey]; ok {
			useShipperVal, ok := useShipperRaw.(bool)
			if !ok {
				return nil, fmt.Errorf("invalid 'outputs.%s.use_shipper', expected a bool not a %T", name, useShipperRaw)
			}
			useShipper = useShipperVal
			delete(output, useShipperKey)
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
			config:     output,
			inputs:     make(map[string][]inputI),
			useShipper: useShipper,
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
		if outputRaw, ok := input[useOutputKey]; ok {
			outputNameVal, ok := outputRaw.(string)
			if !ok {
				return nil, fmt.Errorf("invalid 'inputs.%d.use_output', expected a string not a %T", idx, outputRaw)
			}
			outputName = outputNameVal
			delete(input, useOutputKey)
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

		// Inject the top level fleet policy revision into each input configuration. This
		// allows individual inputs (like endpoint) to detect policy changes more easily.
		injectInputPolicyID(policy, input)

		output.inputs[t] = append(output.inputs[t], inputI{
			idx:       idx,
			id:        id,
			enabled:   enabled,
			logLevel:  logLevel,
			inputType: t,
			config:    input,
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
	inputType string // canonical (non-alias) type

	// The raw configuration for this input, with small cleanups:
	// - enabled key is removed
	// - the key "policy.revision" is set to the current fleet policy revision
	// TODO: list incomplete
	config map[string]interface{}
}

type outputI struct {
	name       string
	enabled    bool
	logLevel   client.UnitLogLevel
	outputType string

	// The raw configuration for this output, with small cleanups:
	// - enabled key is removed
	// - log_level key is removed
	// - use_shipper key is removed
	// - if outputType is "elasticsearch", headers key is extended by adding any
	//   values in AgentInfo.esHeaders
	config map[string]interface{}

	// inputs directed at this output, keyed by canonical (non-alias) type.
	inputs map[string][]inputI

	// If true, RuntimeSpecs should use a shipper for this output.
	useShipper bool
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

func validateRuntimeChecks(
	runtime *RuntimeSpec,
	platform PlatformDetail,
) error {
	vars, err := varsForPlatform(platform)
	if err != nil {
		return err
	}
	for _, prevention := range runtime.Preventions {
		expression, err := eql.New(prevention.Condition)
		if err != nil {
			// this should not happen because the specification already validates that this
			// should never error; but just in-case we consider this a reason to prevent the running of the input
			return NewErrInputRuntimeCheckFail(err.Error())
		}
		preventionTrigger, err := expression.Eval(vars, false)
		if err != nil {
			// error is considered a failure and reported as a reason
			return NewErrInputRuntimeCheckFail(err.Error())
		}
		if preventionTrigger {
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
