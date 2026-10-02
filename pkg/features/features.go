// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package features

import (
	"fmt"
	"sync"

	ucfg "github.com/elastic/go-ucfg"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/config"

	"google.golang.org/protobuf/types/known/structpb"
)

// The default value of tamper protection flag if the flag is missing
// The following was agreed upon for upcoming releases
// 8.10  - default is disabled
// 8.11+ - default is enabled
const defaultTamperProtection = true

// The default value of the disable policy change acks flag if the flag is missing.
// 9.2 - disabled (acks are sent)
const defaultDisablePolicyChangeAcks = false

// The default value for standalone encrypted config.
// 9.4 - disabled (plaintext config)
const defaultEncryptedConfig = false

var (
	current = Flags{
		tamperProtection:  defaultTamperProtection,
		defaultProcessors: defaultProcessors(),
	}
)

// DefaultProcessors holds per-processor enable/disable flags for the
// by default enabled Beat add_x_metadata processors.
type DefaultProcessors struct {
	AddHostMetadata       bool `config:"add_host_metadata" yaml:"add_host_metadata"`
	AddCloudMetadata      bool `config:"add_cloud_metadata" yaml:"add_cloud_metadata"`
	AddDockerMetadata     bool `config:"add_docker_metadata" yaml:"add_docker_metadata"`
	AddKubernetesMetadata bool `config:"add_kubernetes_metadata" yaml:"add_kubernetes_metadata"`
}

// Unpack implements ucfg.ConfigUnpacker. It initialises all flags to true
// before overlaying values from c, so absent fields remain enabled.
// As a convenience, setting enabled: false sets all processors
// disabled.
func (dp *DefaultProcessors) Unpack(c *ucfg.Config) error {
	var rootEnabledFlag struct {
		Enabled *bool `config:"enabled"`
	}
	if err := c.Unpack(&rootEnabledFlag); err != nil {
		return err
	}
	// "enabled:" sets the default for any unspecified individual flag.
	// Absent or true → default all on; false → default all off.
	// Individual flags always override enabled:.
	if rootEnabledFlag.Enabled == nil || *rootEnabledFlag.Enabled {
		*dp = defaultProcessors()
	}
	// noUnpack is a local type alias for DefaultProcessors that does not
	// inherit the Unpack method, preventing infinite recursion when ucfg
	// unpacks the struct fields.
	type noUnpack DefaultProcessors
	return c.Unpack((*noUnpack)(dp))
}

func defaultProcessors() DefaultProcessors {
	return DefaultProcessors{
		AddHostMetadata:       true,
		AddCloudMetadata:      true,
		AddDockerMetadata:     true,
		AddKubernetesMetadata: true,
	}
}

// IsEnabled reports whether the named processor is enabled. Non-metadata
// processor names (those not tracked by a dedicated flag) always return true.
func (dp DefaultProcessors) IsEnabled(name string) bool {
	switch name {
	case "add_host_metadata":
		return dp.AddHostMetadata
	case "add_cloud_metadata":
		return dp.AddCloudMetadata
	case "add_docker_metadata":
		return dp.AddDockerMetadata
	case "add_kubernetes_metadata":
		return dp.AddKubernetesMetadata
	default:
		return true
	}
}

// Restrict returns new flags where each field is true only if it is true in
// both f and other. This implements the per-output restriction model: per-output
// settings can only disable processors that are globally enabled, not re-enable
// globally disabled ones.
func (dp DefaultProcessors) Restrict(other DefaultProcessors) DefaultProcessors {
	return DefaultProcessors{
		AddHostMetadata:       dp.AddHostMetadata && other.AddHostMetadata,
		AddCloudMetadata:      dp.AddCloudMetadata && other.AddCloudMetadata,
		AddDockerMetadata:     dp.AddDockerMetadata && other.AddDockerMetadata,
		AddKubernetesMetadata: dp.AddKubernetesMetadata && other.AddKubernetesMetadata,
	}
}

type BoolValueOnChangeCallback func(new, old bool)

type Flags struct {
	mu     sync.RWMutex
	source *structpb.Struct

	fqdn          bool
	fqdnCallbacks map[string]BoolValueOnChangeCallback

	tamperProtection        bool
	disablePolicyChangeAcks bool
	defaultProcessors       DefaultProcessors
	encryptedConfig         bool
}

type cfg struct {
	Agent struct {
		Features struct {
			FQDN struct {
				Enabled bool `json:"enabled" yaml:"enabled" config:"enabled"`
			} `json:"fqdn" yaml:"fqdn" config:"fqdn"`
			TamperProtection *struct {
				Enabled bool `json:"enabled" yaml:"enabled" config:"enabled"`
			} `json:"tamper_protection,omitempty" yaml:"tamper_protection,omitempty" config:"tamper_protection,omitempty"`
			DisablePolicyChangeAcks *struct {
				Enabled bool `json:"enabled" yaml:"enabled" config:"enabled"`
			} `json:"disable_policy_change_acks" yaml:"disable_policy_change_acks" config:"disable_policy_change_acks"`
			DefaultProcessors *DefaultProcessors `json:"default_processors,omitempty" yaml:"default_processors,omitempty" config:"default_processors,omitempty"`
			EncryptedConfig   *struct {
				Enabled bool `json:"enabled" yaml:"enabled" config:"enabled"`
			} `json:"encrypted_config" yaml:"encrypted_config" config:"encrypted_config"`
		} `json:"features" yaml:"features" config:"features"`
	} `json:"agent" yaml:"agent" config:"agent"`
}

func (f *Flags) FQDN() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.fqdn
}

func (f *Flags) TamperProtection() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.tamperProtection
}

func (f *Flags) DisablePolicyChangeAcks() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.disablePolicyChangeAcks
}

func (f *Flags) DefaultProcessors() DefaultProcessors {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.defaultProcessors
}

func (f *Flags) EncryptedConfig() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.encryptedConfig
}

func (f *Flags) AsProto() *proto.Features {
	return &proto.Features{
		Fqdn: &proto.FQDNFeature{
			Enabled: f.FQDN(),
		},
		Source: f.source,
	}
}

// AddFQDNOnChangeCallback takes a callback function that will be called with the new and old values
// of `flags.fqdnEnabled` whenever it changes. It also takes a string ID - this is useful
// in calling `RemoveFQDNOnChangeCallback` to de-register the callback.
func AddFQDNOnChangeCallback(cb BoolValueOnChangeCallback, id string) error {
	current.mu.Lock()
	defer current.mu.Unlock()

	// Initialize callbacks map if necessary.
	if current.fqdnCallbacks == nil {
		current.fqdnCallbacks = map[string]BoolValueOnChangeCallback{}
	}

	current.fqdnCallbacks[id] = cb
	return nil
}

// RemoveFQDNOnChangeCallback removes the callback function associated with the given ID (originally
// returned by `AddFQDNOnChangeCallback` so that function will be no longer be called when
// `flags.fqdnEnabled` changes.
func RemoveFQDNOnChangeCallback(id string) {
	current.mu.Lock()
	defer current.mu.Unlock()

	delete(current.fqdnCallbacks, id)
}

// setFQDN sets the value of the FQDN flag in Flags.
func (f *Flags) setFQDN(newValue bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	oldValue := f.fqdn
	f.fqdn = newValue
	for _, cb := range f.fqdnCallbacks {
		cb(newValue, oldValue)
	}
}

// setTamperProtection sets the value of the TamperProtection flag in Flags.
func (f *Flags) setTamperProtection(newValue bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.tamperProtection = newValue
}

func (f *Flags) setDisablePolicyChangeAcks(newValue bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.disablePolicyChangeAcks = newValue
}

func (f *Flags) setDefaultProcessors(newValue DefaultProcessors) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.defaultProcessors = newValue
}

func (f *Flags) setEncryptedConfig(newValue bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.encryptedConfig = newValue
}

// setSource preserves the original agent.features subtree so consumers can
// receive feature flags that are not represented by typed Agent fields.
func (f *Flags) setSource(c *config.Config) error {
	options := make([]interface{}, len(config.NoResolveOptions))
	for i, option := range config.NoResolveOptions {
		options[i] = option
	}

	var policy map[string]any
	if err := c.UnpackTo(&policy, options...); err != nil {
		return fmt.Errorf("could not unpack feature flags source: %w", err)
	}

	featureConfig := map[string]any{}
	if agentConfig, ok := policy["agent"].(map[string]any); ok {
		if configuredFeatures, ok := agentConfig["features"].(map[string]any); ok {
			featureConfig = configuredFeatures
		}
	}

	source, err := structpb.NewStruct(map[string]any{
		"agent": map[string]any{
			"features": featureConfig,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to create source from feature flags configuration: %w", err)
	}

	f.source = source
	return nil
}

// Parse receives a policy, parses and returns it.
// policy can be a *config.Config, config.Config or anything config.NewConfigFrom
// can work with. If policy is nil, Parse is a no-op.
func Parse(policy any) (*Flags, error) {
	if policy == nil {
		return nil, nil
	}

	var c *config.Config
	switch policy.(type) {
	case *config.Config:
		c = (policy).(*config.Config)
	case config.Config:
		aa := (policy).(config.Config)
		c = &aa
	default:
		var err error
		c, err = config.NewConfigFrom(policy)
		if err != nil {
			return nil, fmt.Errorf("could not get a config from type %T: %w",
				policy, err)
		}
	}

	if c == nil {
		return nil, nil
	}

	parsedFlags := cfg{}
	if err := c.UnpackTo(&parsedFlags); err != nil {
		return nil, fmt.Errorf("could not umpack features config: %w", err)
	}

	flags := new(Flags)
	flags.setFQDN(parsedFlags.Agent.Features.FQDN.Enabled)

	// Tamper protection flag is optional, fallback on default value if missing
	if parsedFlags.Agent.Features.TamperProtection != nil {
		flags.setTamperProtection(parsedFlags.Agent.Features.TamperProtection.Enabled)
	} else {
		flags.setTamperProtection(defaultTamperProtection)
	}

	if parsedFlags.Agent.Features.DisablePolicyChangeAcks != nil {
		flags.setDisablePolicyChangeAcks(parsedFlags.Agent.Features.DisablePolicyChangeAcks.Enabled)
	} else {
		flags.setDisablePolicyChangeAcks(defaultDisablePolicyChangeAcks)
	}

	dp := defaultProcessors()
	if parsedFlags.Agent.Features.DefaultProcessors != nil {
		dp = *parsedFlags.Agent.Features.DefaultProcessors
	}
	flags.setDefaultProcessors(dp)

	if parsedFlags.Agent.Features.EncryptedConfig != nil {
		flags.setEncryptedConfig(parsedFlags.Agent.Features.EncryptedConfig.Enabled)
	} else {
		flags.setEncryptedConfig(defaultEncryptedConfig)
	}

	if err := flags.setSource(c); err != nil {
		return nil, fmt.Errorf("error creating feature flags source: %w", err)
	}

	return flags, nil
}

// Apply receives a config and applies it. If c is nil, Apply is a no-op.
func Apply(c *config.Config) error {
	if c == nil {
		return nil
	}

	var err error

	parsed, err := Parse(c) // Updating global state
	if err != nil {
		return fmt.Errorf("could not apply feature flag config: %w", err)
	}

	current.setFQDN(parsed.FQDN())
	current.setTamperProtection(parsed.TamperProtection())
	current.setDisablePolicyChangeAcks(parsed.DisablePolicyChangeAcks())
	current.setDefaultProcessors(parsed.DefaultProcessors())
	current.setEncryptedConfig(parsed.EncryptedConfig())
	return err
}

// FQDN reports if FQDN should be used instead of hostname for host.name.
func FQDN() bool {
	return current.FQDN()
}

// TamperProtection reports if tamper protection feature is enabled
func TamperProtection() bool {
	return current.TamperProtection()
}

// DisablePolicyChangeAcks reports if the agent will stop using ACKs for POLICY_CHANGE actions.
func DisablePolicyChangeAcks() bool {
	return current.DisablePolicyChangeAcks()
}

// GetDefaultProcessors returns the default processor flags controlling which
// default beat metadata processors are applied.
func GetDefaultProcessors() DefaultProcessors {
	return current.DefaultProcessors()
}

func EncryptedConfig() bool {
	return current.EncryptedConfig()
}
