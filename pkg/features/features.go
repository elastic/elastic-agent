// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package features

import (
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

var (
	current = Flags{}
)

type Flags struct {
	mu sync.RWMutex

	fqdn bool
}

func (f *Flags) FQDN() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.fqdn
}

// SetFQDN sets the value of the FQDN flag in Flags.
func (f *Flags) SetFQDN(newValue bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.fqdn = newValue
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

	type cfg struct {
		Agent struct {
			Features struct {
				FQDN *config.Config `json:"fqdn" yaml:"fqdn" config:"fqdn"`
			} `json:"features" yaml:"features" config:"features"`
		} `json:"agent" yaml:"agent" config:"agent"`
	}

	parsedFlags := cfg{}
	if err := c.Unpack(&parsedFlags); err != nil {
		return nil, fmt.Errorf("could not umpack features config: %w", err)
	}

	flags := new(Flags)
	flags.SetFQDN(parsedFlags.Agent.Features.FQDN.Enabled())

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

	current.SetFQDN(parsed.FQDN())
	return err
}

// FQDN reports if FQDN should be used instead of hostname for host.name.
func FQDN() bool {
	return current.FQDN()
}

func (f *Flags) AsProto() *proto.Features {
	return &proto.Features{
		Fqdn: &proto.FQDNFeature{
			Enabled: f.FQDN(),
		},
	}
}
