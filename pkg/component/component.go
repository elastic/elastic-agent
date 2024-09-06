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

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install/pkgmgr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/eql"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/limits"
)

// GenerateMonitoringCfgFn is a function that can inject information into the model generation process.
type GenerateMonitoringCfgFn func(map[string]interface{}, []Component, map[string]string, map[string]uint64) (map[string]interface{}, error)

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
	Data      string `yaml:"data"`      // Signed base64 encoded json bytes
	Signature string `yaml:"signature"` // Signature
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

type ElasticAPM config.APMConfig

type APMConfig struct {
	Elastic *ElasticAPM `yaml:"elastic"`
}

// Component is a set of units that needs to run.
type Component struct {
	// ID is the unique ID of the component.
	ID string `yaml:"id"`

	// Err used when there is an error with running this input. Used by the runtime to alert
	// the reason that all of these units are failed.
	Err error `yaml:"-"`
	// the YAML marshaller won't handle `error` values, since they don't implement MarshalYAML()
	// the Component's own MarshalYAML method needs to handle this, and place any error values here instead of `Err`,
	// so they can properly be rendered as a string
	ErrMsg string `yaml:"error,omitempty"`

	// InputSpec on how the input should run.
	InputSpec *InputRuntimeSpec `yaml:"input_spec,omitempty"`

	// The type of the input units.
	InputType string `yaml:"input_type"`

	// The logical output type, i.e. the type of output that was requested.
	OutputType string `yaml:"output_type"`

	// Units that should be running inside this component.
	Units []Unit `yaml:"units"`

	// Features configuration the component should use.
	Features *proto.Features `yaml:"features,omitempty"`

	// Component-level configuration
	Component *proto.Component `yaml:"component,omitempty"`
}

func (c Component) MarshalYAML() (interface{}, error) {
	if c.Err != nil {
		c.ErrMsg = c.Err.Error()
	}
	return c, nil
}

// Type returns the type of the component.
func (c *Component) Type() string {
	if c.InputSpec != nil {
		return c.InputSpec.InputType
	}
	return ""
}

// BinaryName returns the binary name used for the component.
//
// This can differ from the actual binary name that is on disk, when the input specification states that the
// command has a different name.
func (c *Component) BinaryName() string {
	if c.InputSpec != nil {
		if c.InputSpec.Spec.Command != nil && c.InputSpec.Spec.Command.Name != "" {
			return c.InputSpec.Spec.Command.Name
		}
		return c.InputSpec.BinaryName
	}
	return ""
}

// Model is the components model with signed policy data
// This replaces former top level []Components with the top Model that captures signed policy data.
// The signed data is a part of the policy since 8.8.0 release and contains the signed policy fragments and the signature that can be validated.
// The signed data is created and signed by kibana which provides protection from tampering for certain parts of the policy.
//
// The initial idea was that the Agent would validate the signed data if it's present,
// merge the signed data with the policy and dispatch configuration updates to the components.
// The latest Endpoint requirement of not trusting the Agent requires the full signed data with the signature to be passed to Endpoint for validation.
// Endpoint validates the signature and applies the configuration as needed.
//
// The Agent validation of the signature was disabled for 8.8.0 in order to minimize the scope of the change.
// Presently (as of June, 27, 2023) the signature is only validated by Endpoint.
//
// Example of the signed policy property:
// signed:
//
//	data: >-
//	  eyJpZCI6IjBlNjA2OTUwLTE0NTEtMTFlZS04OTI2LTlkZjY4ZjdjMzhlZSIsImFnZW50Ijp7ImZlYXR1cmVzIjp7fSwicHJvdGVjdGlvbiI6eyJlbmFibGVkIjp0cnVlLCJ1bmluc3RhbGxfdG9rZW5faGFzaCI6IjB4MXJ1REo0NVBUYlNuV0V6Yi9xc3VnZHRMNFhKUVRHazU5QitxVEF1OVE9Iiwic2lnbmluZ19rZXkiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVMRHd4Rk1WTjJvSTFmZW9USGJIWmkrUFJuSjZ5TzVzdUw4MktvRXl1M3FTMDB2OGNGVDNlb2JnZG5oT0MxUG9ka0MwVTFmWjhpN1k1TUlzc2szQ2Rzdz09In19LCJpbnB1dHMiOlt7ImlkIjoiZTgyZmQ1ZDEtOTBkOC00NWJjLWE5MTEtOTU1OTBjNDRjYTc1IiwibmFtZSI6IkVQIiwicmV2aXNpb24iOjEsInR5cGUiOiJlbmRwb2ludCJ9XX0=
//	signature: >-
//	  MEUCIQCpQR8WES3X4gjptjIWtLdqJT0QLRVz5bUnTlG3xt4LfQIgW5ioOoaAUII4G0b74vWGSLSD7sQ6uAdqgZoNF33vSbM=
//
// Example of decoded signed.data from above:
//
//	{
//	  "id": "0e606950-1451-11ee-8926-9df68f7c38ee",
//	  "agent": {
//	    "features": {},
//	    "protection": {
//	      "enabled": true,
//	      "uninstall_token_hash": "0x1ruDJ45PTbSnWEzb/qsugdtL4XJQTGk59B+qTAu9Q=",
//	      "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELDwxFMVN2oI1feoTHbHZi+PRnJ6yO5suL82KoEyu3qS00v8cFT3eobgdnhOC1PodkC0U1fZ8i7Y5MIssk3Cdsw=="
//	    }
//	  },
//	  "inputs": [
//	    {
//	      "id": "e82fd5d1-90d8-45bc-a911-95590c44ca75",
//	      "name": "EP",
//	      "revision": 1,
//	      "type": "endpoint"
//	    }
//	  ]
//	}
//
// The signed.data JSON has exact same shape/schema as the policy.
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
	currentServiceCompInts map[string]uint64,
) ([]Component, error) {
	components, err := r.PolicyToComponents(policy, ll, headers)
	if err != nil {
		return nil, err
	}

	if monitoringInjector != nil {
		// The monitoring config depends on a map from component id to
		// binary name
		binaryMapping := make(map[string]string)
		for _, component := range components {
			binaryMapping[component.ID] = component.BinaryName()
		}
		monitoringCfg, err := monitoringInjector(policy, components, binaryMapping, currentServiceCompInts)
		if err != nil {
			return nil, fmt.Errorf("failed to inject monitoring: %w", err)
		}

		if monitoringCfg != nil {
			// monitoring is enabled
			monitoringComps, err := r.PolicyToComponents(monitoringCfg, ll, headers)
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

// Collect all inputs of the given type going to the given output and return
// the resulting Components. The returned Components may have no units if no
// active inputs were found.
func (r *RuntimeSpecs) componentsForInputType(
	inputType string,
	output outputI,
	featureFlags *features.Flags,
	componentConfig *ComponentConfig,
) []Component {
	var components []Component
	inputSpec, componentErr := r.GetInput(inputType)

	// Treat as non isolated units component on error of reading the input spec
	if componentErr != nil || !inputSpec.Spec.IsolateUnits {
		componentID := fmt.Sprintf("%s-%s", inputType, output.name)
		if componentErr == nil && !containsStr(inputSpec.Spec.Outputs, output.outputType) {
			// This output is unsupported.
			componentErr = ErrOutputNotSupported
		}

		var units []Unit
		for _, input := range output.inputs[inputType] {
			if input.enabled {
				unitID := fmt.Sprintf("%s-%s", componentID, input.id)
				units = append(units, unitForInput(input, unitID))
			}
		}

		if len(units) > 0 {
			// Populate the output units for this component
			units = append(units, unitForOutput(output, componentID))
			components = append(components, Component{
				ID:         componentID,
				Err:        componentErr,
				InputSpec:  &inputSpec,
				InputType:  inputType,
				OutputType: output.outputType,
				Units:      units,
				Features:   featureFlags.AsProto(),
				Component:  componentConfig.AsProto(),
			})
		}
	} else {
		for _, input := range output.inputs[inputType] {
			// Units are being mapped to components, so we need a unique ID for each.
			componentID := fmt.Sprintf("%s-%s-%s", inputType, output.name, input.id)
			if componentErr == nil && !containsStr(inputSpec.Spec.Outputs, output.outputType) {
				// This output is unsupported.
				componentErr = ErrOutputNotSupported
			}

			var units []Unit
			if input.enabled {
				unitID := fmt.Sprintf("%s-unit", componentID)
				units = append(units, unitForInput(input, unitID))

				// each component gets its own output, because of unit isolation
				units = append(units, unitForOutput(output, componentID))
				components = append(components, Component{
					ID:         componentID,
					Err:        componentErr,
					InputSpec:  &inputSpec,
					InputType:  inputType,
					OutputType: output.outputType,
					Units:      units,
					Features:   featureFlags.AsProto(),
					Component:  componentConfig.AsProto(),
				})
			}
		}
	}
	return components
}

func (r *RuntimeSpecs) componentsForOutput(output outputI, featureFlags *features.Flags, componentConfig *ComponentConfig) []Component {
	var components []Component
	for inputType := range output.inputs {
		// No need for error checking at this stage -- we are guaranteed
		// to get a Component/s back. If there is an error that prevents it/them
		// from running then it will be in the Component's Err field and
		// we will report it later. The only thing we skip is a component/s
		// with no units.
		typeComponents := r.componentsForInputType(inputType, output, featureFlags, componentConfig)
		for _, component := range typeComponents {
			if len(component.Units) > 0 {
				components = append(components, component)
			}
		}
	}
	return components
}

// PolicyToComponents takes the policy and generates a component model.
func (r *RuntimeSpecs) PolicyToComponents(
	policy map[string]interface{},
	ll logp.Level,
	headers HeadersProvider,
) ([]Component, error) {
	// get feature flags from policy
	featureFlags, err := features.Parse(policy)
	if err != nil {
		return nil, fmt.Errorf("could not parse feature flags from policy: %w", err)
	}

	outputsMap, err := toIntermediate(policy, r.aliasMapping, ll, headers)
	if err != nil {
		return nil, err
	}
	if outputsMap == nil {
		return nil, nil
	}

	// order output keys; ensures result is always the same order
	outputKeys := make([]string, 0, len(outputsMap))
	for k := range outputsMap {
		outputKeys = append(outputKeys, k)
	}
	sort.Strings(outputKeys)

	// get agent limits from the policy
	limits, err := limits.Parse(policy)
	if err != nil {
		return nil, fmt.Errorf("could not parse limits from policy: %w", err)
	}
	// for now it's a shared component configuration for all components
	// subject to change in the future
	componentConfig := &ComponentConfig{
		Limits: ComponentLimits(*limits),
	}

	var components []Component
	for _, outputName := range outputKeys {
		output := outputsMap[outputName]
		if output.enabled {
			components = append(components,
				r.componentsForOutput(output, featureFlags, componentConfig)...)
		}
	}

	return components, nil
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

	// Check if the input configuration defines a policy section.
	if policyObj := inputConfig["policy"]; policyObj != nil {
		// If the policy object converts to map[string]interface{}, inject the revision key.
		// Note that if the interface conversion here fails, we do nothing because we don't
		// know what type of object exists with the policy key.
		if policyMap, ok := policyObj.(map[string]interface{}); ok {
			policyMap["revision"] = revision
		}
	} else {
		// If there was no policy object, then inject one with a revision key.
		inputConfig["policy"] = map[string]interface{}{
			"revision": revision,
		}
	}
}

// toIntermediate takes the policy and returns it into an intermediate representation that is easier to map into a set
// of components.
func toIntermediate(policy map[string]interface{}, aliasMapping map[string]string, ll logp.Level, headers HeadersProvider) (map[string]outputI, error) {
	const (
		outputsKey   = "outputs"
		enabledKey   = "enabled"
		inputsKey    = "inputs"
		typeKey      = "type"
		idKey        = "id"
		useOutputKey = "use_output"
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
			config:     output,
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
	// - the "enabled", "use_output", and "log_level" keys are removed
	// - the key "policy.revision" is set to the current fleet policy revision
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
	// - if outputType is "elasticsearch", headers key is extended by adding any
	//   values in AgentInfo.esHeaders
	config map[string]interface{}

	// inputs directed at this output, keyed by canonical (non-alias) type.
	inputs map[string][]inputI
}

// varsForPlatform sets the runtime variables that are available in the
// input specification runtime checks. This function should always be
// edited in sync with the documentation in specs/README.md.
func varsForPlatform(platform PlatformDetail) (*transpiler.Vars, error) {
	return transpiler.NewVars("", map[string]interface{}{
		"install": map[string]interface{}{
			"in_default": paths.ArePathsEqual(paths.Top(), paths.InstallPath(paths.DefaultBasePath)) || pkgmgr.InstalledViaExternalPkgMgr(),
		},
		"runtime": map[string]interface{}{
			"platform":    platform.String(),
			"os":          platform.OS,
			"arch":        platform.Arch,
			"native_arch": platform.NativeArch,
			"family":      platform.Family,
			"major":       platform.Major,
			"minor":       platform.Minor,
		},
		"user": map[string]interface{}{
			"root": platform.User.Root,
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
	preventionMessages := []string{}
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
			preventionMessages = append(preventionMessages, prevention.Message)
		}
	}
	if len(preventionMessages) > 0 {
		return NewErrInputRuntimeCheckFail(strings.Join(preventionMessages, ", "))
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
