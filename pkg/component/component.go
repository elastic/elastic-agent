// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/eql"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/limits"
)

// GenerateMonitoringCfgFn is a function that can inject information into the model generation process.
type GenerateMonitoringCfgFn func(map[string]interface{}, []Component, map[string]uint64) (map[string]interface{}, error)

type HeadersProvider interface {
	Headers() map[string]string
}

type RuntimeManager string

type RuntimeConfig struct {
	Default       string            `yaml:"default" config:"default" json:"default"`
	Filebeat      BeatRuntimeConfig `yaml:"filebeat" config:"filebeat" json:"filebeat"`
	Metricbeat    BeatRuntimeConfig `yaml:"metricbeat" config:"metricbeat" json:"metricbeat"`
	DynamicInputs string            `yaml:"dynamic_inputs" config:"dynamic_inputs" json:"dynamic_inputs"`
}

type BeatRuntimeConfig struct {
	Default   string            `yaml:"default" config:"default" json:"default"`
	InputType map[string]string `yaml:",inline,omitempty" config:",inline,omitempty" json:",inline,omitempty"`
}

func DefaultRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		Default:       string(DefaultRuntimeManager),
		DynamicInputs: "",
		Metricbeat: BeatRuntimeConfig{
			InputType: map[string]string{
				"activemq/metrics":      string(OtelRuntimeManager),
				"apache/metrics":        string(OtelRuntimeManager),
				"beat/metrics":          string(OtelRuntimeManager),
				"containerd/metrics":    string(OtelRuntimeManager),
				"docker/metrics":        string(OtelRuntimeManager),
				"elasticsearch/metrics": string(OtelRuntimeManager),
				"etcd/metrics":          string(OtelRuntimeManager),
				"http/metrics":          string(OtelRuntimeManager),
				"jolokia/metrics":       string(OtelRuntimeManager),
				"kafka/metrics":         string(OtelRuntimeManager),
				"kibana/metrics":        string(OtelRuntimeManager),
				"linux/metrics":         string(OtelRuntimeManager),
				"logstash/metrics":      string(OtelRuntimeManager),
				"memcached/metrics":     string(OtelRuntimeManager),
				"mongodb/metrics":       string(OtelRuntimeManager),
				"mysql/metrics":         string(OtelRuntimeManager),
				"nats/metrics":          string(OtelRuntimeManager),
				"nginx/metrics":         string(OtelRuntimeManager),
				"rabbitmq/metrics":      string(OtelRuntimeManager),
				"sql/metrics":           string(OtelRuntimeManager),
				"stan/metrics":          string(OtelRuntimeManager),
				"statsd/metrics":        string(OtelRuntimeManager),
				"system/metrics":        string(OtelRuntimeManager),
				"vsphere/metrics":       string(OtelRuntimeManager),
			},
		},
	}
}

func (r *RuntimeConfig) Validate() error {
	validateRuntime := func(val string, allowEmpty bool) error {
		if allowEmpty && val == "" {
			return nil
		}
		switch RuntimeManager(val) {
		case "", OtelRuntimeManager, ProcessRuntimeManager:
			return nil
		default:
			return fmt.Errorf("invalid runtime manager: %s, must be either %s or %s",
				val, OtelRuntimeManager, ProcessRuntimeManager)
		}
	}
	if err := validateRuntime(r.Default, false); err != nil {
		return err
	}
	for _, beatConfig := range []BeatRuntimeConfig{r.Filebeat, r.Metricbeat} {
		if err := validateRuntime(beatConfig.Default, true); err != nil {
			return err
		}
		for _, val := range beatConfig.InputType {
			if err := validateRuntime(val, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *RuntimeConfig) BeatRuntimeConfig(beatName string) *BeatRuntimeConfig {
	switch beatName {
	case "filebeat":
		return &r.Filebeat
	case "metricbeat":
		return &r.Metricbeat
	default:
		return nil
	}
}

func (r *RuntimeConfig) RuntimeManagerForInputType(inputType string, beatName string) RuntimeManager {
	beatRuntimeConfig := r.BeatRuntimeConfig(beatName)
	if beatRuntimeConfig != nil {
		// Check if there's a specific runtime manager for this input type
		if manager, ok := beatRuntimeConfig.InputType[inputType]; ok {
			return RuntimeManager(manager)
		}
		// Check if the beat has a default runtime manager
		if beatRuntimeConfig.Default != "" {
			return RuntimeManager(beatRuntimeConfig.Default)
		}
	}
	// Fall back to global default
	if r.Default != "" {
		return RuntimeManager(r.Default)
	}
	return DefaultRuntimeManager
}

const (
	// defaultUnitLogLevel is the default log level that a unit will get if one is not defined.
	defaultUnitLogLevel                  = client.UnitLogLevelInfo
	headersKey                           = "headers"
	elasticsearchType                    = "elasticsearch"
	workDirPathMod                       = 0o770
	ProcessRuntimeManager                = RuntimeManager("process")
	OtelRuntimeManager                   = RuntimeManager("otel")
	DefaultRuntimeManager RuntimeManager = ProcessRuntimeManager
	enabledKey                           = "enabled"
	typeKey                              = "type"
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

	// The user-assigned name in the original policy for the output config that
	// generated this component's output unit.
	OutputName string `yaml:"output_name"`

	RuntimeManager RuntimeManager `yaml:"-"`

	// An input is considered dynamic if its definition uses variables from dynamic providers. In practice, this
	// indicates that its configuration may change at runtime, possibly very frequently. A component is dynamic if
	// it contains at least one dynamic unit.
	Dynamic bool `yaml:"-"`

	// Units that should be running inside this component.
	Units []Unit `yaml:"units"`

	// Features configuration the component should use.
	Features *proto.Features `yaml:"features,omitempty"`

	// Component-level configuration
	Component *proto.Component `yaml:"component,omitempty"`

	OutputStatusReporting *StatusReporting `yaml:"-"`
}

type StatusReporting struct {
	Enabled bool
}

func (c Component) MarshalYAML() (interface{}, error) {
	if c.Err != nil {
		c.ErrMsg = c.Err.Error()
	}
	return c, nil
}

func (c *Component) MarshalJSON() ([]byte, error) {
	marshalableComponent := struct {
		ID         string `json:"ID"`
		InputType  string `json:"InputType"`
		OutputType string `json:"OutputType"`
		ErrMsg     string `json:"ErrMsg,omitempty"`
		Units      []struct {
			ID     string `json:"ID"`
			ErrMsg string `json:"ErrMsg,omitempty"`
		} `json:"Units"`
	}{
		ID:         c.ID,
		InputType:  c.InputType,
		OutputType: c.OutputType,
	}
	if c.Err != nil {
		marshalableComponent.ErrMsg = c.Err.Error()
	}
	for i := range c.Units {
		marshalableComponent.Units = append(marshalableComponent.Units, struct {
			ID     string `json:"ID"`
			ErrMsg string `json:"ErrMsg,omitempty"`
		}{
			ID: c.Units[i].ID,
		})
		if c.Units[i].Err != nil {
			marshalableComponent.Units[i].ErrMsg = c.Units[i].Err.Error()
		}
	}

	return json.Marshal(marshalableComponent)
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
		return c.InputSpec.CommandName()
	}
	return ""
}

// BeatName returns the beat binary name that would be used to run this component.
func (c *Component) BeatName() string {
	if c.InputSpec != nil {
		return c.InputSpec.BeatName()
	}
	return ""
}

// GetBeatInputIDForUnit returns the ID of the corresponding input or module in the beat configuration for the unit.
// If the unit doesn't run in a beat or isn't an input in the first place, it returns an empty string.
// This function is only needed for the special case where an agent input that runs in a beat process doesn't specify
// streams. Then, the stream name becomes the input id. Reversing this process is necessary when the input runs in
// a beat receiver and we want to translate status back.
// The function can be made fully generic with more effort, the scope was narrowed to make the implementation simpler
// and easier to review.
func (c *Component) GetBeatInputIDForUnit(unitID string) string {
	if c.BeatName() == "" {
		return ""
	}
	found := false
	var unit Unit
	for _, u := range c.Units {
		if u.ID == unitID {
			unit = u
			found = true
			break
		}
	}
	if !found {
		return ""
	}
	if unit.Type == client.UnitTypeOutput {
		return ""
	}
	inputID, found := strings.CutPrefix(unitID, fmt.Sprintf("%s-", c.ID))
	if !found {
		return ""
	}
	return inputID
}

// WorkDirName returns the name of the component's working directory.
func (c *Component) WorkDirName() string {
	return c.ID
}

// WorkDirPath returns the full path of the component's working directory, placing it under the provided parent path.
func (c *Component) WorkDirPath(parentDirPath string) string {
	return filepath.Join(parentDirPath, c.WorkDirName())
}

// PrepareWorkDir prepares the component working directory under the provided parent path. This involves creating
// it under the right ownership and ACLs. This method is idempotent.
func (c *Component) PrepareWorkDir(parentDirPath string) error {
	uid, gid := os.Geteuid(), os.Getegid()
	path := c.WorkDirPath(parentDirPath)
	err := os.MkdirAll(path, workDirPathMod)
	if err != nil {
		return fmt.Errorf("failed to create path %q: %w", path, err)
	}
	if runtime.GOOS == Windows {
		return nil
	}
	err = os.Chown(path, uid, gid)
	if err != nil {
		return fmt.Errorf("failed to chown %q: %w", path, err)
	}
	err = os.Chmod(path, workDirPathMod)
	if err != nil {
		return fmt.Errorf("failed to chmod %q: %w", path, err)
	}
	return nil
}

// RemoveWorkDir removes the component working directory under the provided parent path. This method is idempotent.
func (c *Component) RemoveWorkDir(parentDirPath string) error {
	return os.RemoveAll(c.WorkDirPath(parentDirPath))
}

// ComponentsModifier is a function that takes the computed components model and modifies it before
// passing it into the components runtime manager.
type ComponentsModifier func(comps []Component, cfg map[string]interface{}) ([]Component, error)

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
	runtimeCfg *RuntimeConfig,
	modifiers []ComponentsModifier,
	monitoringInjector GenerateMonitoringCfgFn,
	ll logp.Level,
	headers HeadersProvider,
	currentServiceCompInts map[string]uint64,
	dynamicInputs map[string]bool,
) ([]Component, error) {
	components, err := r.PolicyToComponents(policy, runtimeCfg, ll, headers, dynamicInputs)
	if err != nil {
		return nil, err
	}

	// Do this here so the monitoring injector has a more accurate view of what components are running
	for _, modifier := range modifiers {
		components, err = modifier(components, policy)
		if err != nil {
			return nil, err
		}
	}

	if monitoringInjector != nil {
		monitoringCfg, err := monitoringInjector(policy, components, currentServiceCompInts)
		if err != nil {
			return nil, fmt.Errorf("failed to inject monitoring: %w", err)
		}

		if monitoringCfg != nil {
			// monitoring is enabled
			monitoringComps, err := r.PolicyToComponents(monitoringCfg, runtimeCfg, ll, headers, map[string]bool{})
			if err != nil {
				return nil, fmt.Errorf("failed to generate monitoring components: %w", err)
			}

			for _, modifier := range modifiers {
				monitoringComps, err = modifier(monitoringComps, policy)
				if err != nil {
					return nil, err
				}
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
	cfg, cfgErr := ExpectedConfig(output.Config)
	return Unit{
		ID:       id,
		Type:     client.UnitTypeOutput,
		LogLevel: output.LogLevel,
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
	runtimeConfig *RuntimeConfig,
) []Component {
	var components []Component
	inputSpec, componentErr := r.GetInput(inputType)

	// Treat as non isolated units component on error of reading the input spec
	if componentErr != nil || !inputSpec.Spec.IsolateUnits {
		// Components are generally identified by their input type and output name. However, for
		// Service Runtime components, there can only ever be a single instance of the component running,
		// as a service. So we identify these only by their input type. This way, if the output for a service
		// component were to change, it would not result in a different ID for that component. By keeping the same
		// ID, we prevent the component from being identified as a new one and the corresponding service from being
		// unnecessarily stopped and started.
		componentID := fmt.Sprintf("%s-%s", inputType, output.Name)
		if inputSpec.Spec.Service != nil {
			componentID = inputType
		}

		if componentErr == nil && !containsStr(inputSpec.Spec.Outputs, output.OutputType) {
			// This output is unsupported.
			componentErr = ErrOutputNotSupported
		}

		unitsForRuntimeManager := make(map[RuntimeManager][]Unit)
		var hasDynamicInputs bool
		for _, input := range output.Inputs[inputType] {
			if input.enabled {
				unitID := GetInputUnitId(componentID, input.id)
				if input.runtimeManager == "" {
					input.runtimeManager = runtimeConfig.RuntimeManagerForInputType(input.inputType, inputSpec.BeatName())
				}
				unitsForRuntimeManager[input.runtimeManager] = append(
					unitsForRuntimeManager[input.runtimeManager],
					unitForInput(input, unitID),
				)
				hasDynamicInputs = hasDynamicInputs || input.dynamic
			}
		}

		// sort to ensure consistent order
		runtimeManagers := slices.Collect(maps.Keys(unitsForRuntimeManager))
		slices.Sort(runtimeManagers)
		for _, runtimeManager := range runtimeManagers {
			units := unitsForRuntimeManager[runtimeManager]
			if len(units) > 0 {
				// Populate the output units for this component
				units = append(units, unitForOutput(output, componentID))
				components = append(components, Component{
					ID:                    componentID,
					Err:                   componentErr,
					InputSpec:             &inputSpec,
					InputType:             inputType,
					OutputType:            output.OutputType,
					OutputName:            output.Name,
					Units:                 units,
					RuntimeManager:        runtimeManager,
					Dynamic:               hasDynamicInputs,
					Features:              featureFlags.AsProto(),
					Component:             componentConfig.AsProto(),
					OutputStatusReporting: extractStatusReporting(output.Config),
				})
			}
		}
	} else {
		for _, input := range output.Inputs[inputType] {
			// Units are being mapped to components, so we need a unique ID for each.
			// Components are generally identified by their input type and output name. However, for
			// Service Runtime components, there can only ever be a single instance of the component running,
			// as a service. So we identify these only by their input type. This way, if the output for a service
			// component were to change, it would not result in a different ID for that component. By keeping the same
			// ID, we prevent the component from being identified as a new one and the corresponding service from being
			// unnecessarily stopped and started.
			componentID := fmt.Sprintf("%s-%s-%s", inputType, output.Name, input.id)
			if inputSpec.Spec.Service != nil {
				componentID = fmt.Sprintf("%s-%s", inputType, input.id)
			}

			if componentErr == nil && !containsStr(inputSpec.Spec.Outputs, output.OutputType) {
				// This output is unsupported.
				componentErr = ErrOutputNotSupported
			}

			if input.runtimeManager == "" {
				input.runtimeManager = runtimeConfig.RuntimeManagerForInputType(input.inputType, inputSpec.BeatName())
			}

			var units []Unit
			if input.enabled {
				unitID := GetOutputUnitId(componentID)
				units = append(units, unitForInput(input, unitID))

				// each component gets its own output, because of unit isolation
				units = append(units, unitForOutput(output, componentID))
				components = append(components, Component{
					ID:                    componentID,
					Err:                   componentErr,
					InputSpec:             &inputSpec,
					InputType:             inputType,
					OutputType:            output.OutputType,
					OutputName:            output.Name,
					Units:                 units,
					RuntimeManager:        input.runtimeManager,
					Dynamic:               input.dynamic,
					Features:              featureFlags.AsProto(),
					Component:             componentConfig.AsProto(),
					OutputStatusReporting: extractStatusReporting(output.Config),
				})
			}
		}
	}
	return components
}

func (r *RuntimeSpecs) componentsForOutput(
	output outputI,
	featureFlags *features.Flags,
	componentConfig *ComponentConfig,
	runtimeConfig *RuntimeConfig,
) []Component {
	var components []Component
	for inputType := range output.Inputs {
		// No need for error checking at this stage -- we are guaranteed
		// to get a Component/s back. If there is an error that prevents it/them
		// from running then it will be in the Component's Err field and
		// we will report it later. The only thing we skip is a component/s
		// with no units.
		typeComponents := r.componentsForInputType(inputType, output, featureFlags, componentConfig, runtimeConfig)
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
	runtimeCfg *RuntimeConfig,
	ll logp.Level,
	headers HeadersProvider,
	dynamicInputs map[string]bool,
) ([]Component, error) {
	// get feature flags from policy
	featureFlags, err := features.Parse(policy)
	if err != nil {
		return nil, fmt.Errorf("could not parse feature flags from policy: %w", err)
	}

	outputsMap, err := toIntermediate(policy, r.aliasMapping, ll, headers, dynamicInputs)
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
		if output.Enabled {
			components = append(components,
				r.componentsForOutput(output, featureFlags, componentConfig, runtimeCfg)...)
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
func toIntermediate(
	policy map[string]interface{},
	aliasMapping map[string]string,
	ll logp.Level,
	headers HeadersProvider,
	dynamicInputs map[string]bool,
) (map[string]outputI, error) {
	const (
		outputsKey        = "outputs"
		enabledKey        = "enabled"
		inputsKey         = "inputs"
		typeKey           = "type"
		idKey             = "id"
		useOutputKey      = "use_output"
		runtimeManagerKey = "_runtime_experimental"
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
		parsedOutput, err := ParseOutput(name, output, ll, headers)
		if err != nil {
			return nil, err
		}

		outputsMap[name] = *parsedOutput
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

		var runtimeManager RuntimeManager
		// determine the runtime manager for the input
		if runtimeManagerRaw, ok := input[runtimeManagerKey]; ok {
			runtimeManagerStr, ok := runtimeManagerRaw.(string)
			if !ok {
				return nil, fmt.Errorf("invalid 'inputs.%d.runtime', expected a string, not a %T", idx, runtimeManagerRaw)
			}
			runtimeManagerVal := RuntimeManager(runtimeManagerStr)
			switch runtimeManagerVal {
			case OtelRuntimeManager, ProcessRuntimeManager:
			default:
				return nil, fmt.Errorf("invalid 'inputs.%d.runtime', valid values are: %s, %s", idx, OtelRuntimeManager, ProcessRuntimeManager)
			}
			runtimeManager = runtimeManagerVal
			delete(input, runtimeManagerKey)
		}

		// Inject the top level fleet policy revision into each input configuration. This
		// allows individual inputs (like endpoint) to detect policy changes more easily.
		injectInputPolicyID(policy, input)

		output.Inputs[t] = append(output.Inputs[t], inputI{
			idx:            idx,
			id:             id,
			enabled:        enabled,
			logLevel:       logLevel,
			inputType:      t,
			config:         input,
			runtimeManager: runtimeManager,
			dynamic:        dynamicInputs[id],
		})
	}
	if len(outputsMap) == 0 {
		return nil, nil
	}
	return outputsMap, nil
}

// ParseOutput parses the output configuration into an intermediate structured representation.
func ParseOutput(outputName string, outputConfig map[string]any, ll logp.Level, headers HeadersProvider) (*outputI, error) {
	typeRaw, ok := outputConfig[typeKey]
	if !ok {
		return nil, fmt.Errorf("invalid 'outputs.%s', 'type' missing", outputName)
	}
	t, ok := typeRaw.(string)
	if !ok {
		return nil, fmt.Errorf("invalid 'outputs.%s.type', expected a string not a %T", outputName, typeRaw)
	}
	enabled := true
	if enabledRaw, ok := outputConfig[enabledKey]; ok {
		enabledVal, ok := enabledRaw.(bool)
		if !ok {
			return nil, fmt.Errorf("invalid 'outputs.%s.enabled', expected a bool not a %T", outputName, enabledRaw)
		}
		enabled = enabledVal
		delete(outputConfig, enabledKey)
	}
	logLevel, err := getLogLevel(outputConfig, ll)
	if err != nil {
		return nil, fmt.Errorf("invalid 'outputs.%s.log_level', %w", outputName, err)
	}

	// inject headers configured during enroll
	if t == elasticsearchType && headers != nil {
		// can be nil when called from install/uninstall
		if agentHeaders := headers.Headers(); len(agentHeaders) > 0 {
			headers := make(map[string]interface{})
			if existingHeadersRaw, found := outputConfig[headersKey]; found {
				existingHeaders, ok := existingHeadersRaw.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("invalid 'outputs.headers', expected a map not a %T", outputConfig)
				}
				headers = existingHeaders
			}

			for headerName, headerVal := range agentHeaders {
				// only set headers for those that are not already set
				if _, ok := headers[headerName]; !ok {
					headers[headerName] = headerVal
				}
			}

			outputConfig[headersKey] = headers
		}
	}

	return &outputI{
		Name:       outputName,
		Enabled:    enabled,
		LogLevel:   logLevel,
		OutputType: t,
		Config:     outputConfig,
		Inputs:     make(map[string][]inputI),
	}, nil
}

type inputI struct {
	idx            int
	id             string
	enabled        bool
	logLevel       client.UnitLogLevel
	inputType      string // canonical (non-alias) type
	runtimeManager RuntimeManager
	// An input is considered dynamic if its definition uses variables from dynamic providers. In practice, this
	// indicates that its configuration may change at runtime, possibly very frequently.
	dynamic bool

	// The raw configuration for this input, with small cleanups:
	// - the "enabled", "use_output", and "log_level" keys are removed
	// - the key "policy.revision" is set to the current fleet policy revision
	config map[string]interface{}
}

type outputI struct {
	Name       string
	Enabled    bool
	LogLevel   client.UnitLogLevel
	OutputType string

	// The raw configuration for this output, with small cleanups:
	// - enabled key is removed
	// - log_level key is removed
	// - if outputType is "elasticsearch", headers key is extended by adding any
	//   values in AgentInfo.esHeaders
	Config map[string]interface{}

	// inputs directed at this output, keyed by canonical (non-alias) type.
	Inputs map[string][]inputI
}

// varsForPlatform sets the runtime variables that are available in the
// input specification runtime checks. This function should always be
// edited in sync with the documentation in specs/README.md.
func varsForPlatform(platform PlatformDetail, defaultProvider string) (*transpiler.Vars, error) {
	return transpiler.NewVars("", map[string]interface{}{
		"install": map[string]interface{}{
			"in_default": paths.ArePathsEqual(paths.Top(), paths.InstallPath(paths.DefaultBasePath)) || platform.IsInstalledViaExternalPkgMgr,
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
	}, nil, defaultProvider)
}

func validateRuntimeChecks(
	runtime *RuntimeSpec,
	platform PlatformDetail,
) error {
	vars, err := varsForPlatform(platform, "") // no default provider
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
		for _, i := range o.Inputs {
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

func extractStatusReporting(cfg map[string]interface{}) *StatusReporting {
	const statusReportingKey = "status_reporting"
	srRaw, ok := cfg[statusReportingKey]
	if !ok {
		return nil
	}
	srMap, ok := srRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	enabledRaw, ok := srMap["enabled"]
	if !ok {
		return nil
	}
	enabled, ok := enabledRaw.(bool)
	if !ok {
		return nil
	}
	return &StatusReporting{
		Enabled: enabled,
	}
}

func GetInputUnitId(componentID string, inputID string) string {
	return fmt.Sprintf("%s-%s", componentID, inputID)
}

func GetOutputUnitId(componentID string) string {
	return fmt.Sprintf("%s-unit", componentID)
}
