// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package features

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/config"

	"google.golang.org/protobuf/types/known/structpb"
)

var (
	current = Flags{}
)

type BoolValueOnChangeCallback func(new, old bool)

type Flags struct {
	mu     sync.RWMutex
	source *structpb.Struct

	fqdn          bool
	fqdnCallbacks map[string]BoolValueOnChangeCallback
}

type cfg struct {
	Agent struct {
		Features struct {
			FQDN struct {
				Enabled bool `json:"enabled" yaml:"enabled" config:"enabled"`
			} `json:"fqdn" yaml:"fqdn" config:"fqdn"`
		} `json:"features" yaml:"features" config:"features"`
	} `json:"agent" yaml:"agent" config:"agent"`
}

func (f *Flags) FQDN() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.fqdn
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

// setSource sets the source from he given cfg.
func (f *Flags) setSource(c cfg) error {
	// Use JSON marshalling-unmarshalling to convert cfg to mapstr
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("could not convert feature flags configuration to JSON: %w", err)
	}

	var s map[string]interface{}
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("could not convert feature flags JSON to mapstr: %w", err)
	}

	source, err := structpb.NewStruct(s)
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
	if err := c.Unpack(&parsedFlags); err != nil {
		return nil, fmt.Errorf("could not umpack features config: %w", err)
	}

	flags := new(Flags)
	flags.setFQDN(parsedFlags.Agent.Features.FQDN.Enabled)
	if err := flags.setSource(parsedFlags); err != nil {
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
	return err
}

// FQDN reports if FQDN should be used instead of hostname for host.name.
func FQDN() bool {
	return current.FQDN()
}
