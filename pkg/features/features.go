// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package features

import (
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

var (
	// current flagsCfg
	mu sync.Mutex

	current Flags
)

type Flags struct {
	FQDN bool
}

// Parse receives a policy, parses and returns it.
// policy can be a *config.Config, config.Config or anything config.NewConfigFrom
// can work with.
func Parse(policy any) (Flags, error) {
	if policy == nil {
		return Flags{}, nil
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
			return Flags{}, fmt.Errorf("could not get a config from type %T: %w",
				policy, err)
		}
	}

	type cfg struct {
		Agent struct {
			Features struct {
				FQDN *config.Config `json:"fqdn" yaml:"fqdn" config:"fqdn"`
			} `json:"features" yaml:"features" config:"features"`
		} `json:"agent" yaml:"agent" config:"agent"`
	}

	if c == nil {
		logp.L().Infof("feature current nil config, nothing to do: fqdn")

		return Flags{}, nil
	}

	parsedFlags := cfg{}
	if err := c.Unpack(&parsedFlags); err != nil {
		return Flags{}, fmt.Errorf("could not umpack features config: %w", err)
	}

	logp.L().Infof("feature current parsed: fqdn: %t",
		parsedFlags.Agent.Features.FQDN.Enabled())

	return Flags{FQDN: parsedFlags.Agent.Features.FQDN.Enabled()}, nil
}

// Apply receives a policy,
func Apply(c *config.Config) (Flags, error) {
	var err error

	mu.Lock()
	defer mu.Unlock()
	// Updating global state
	current, err = Parse(c)

	logp.L().Infof("features.Apply: fqdn: %t",
		current.FQDN)

	return current, err
}

// FQDN reports if FQDN should be used instead of hostname for host.name.
func FQDN() bool {
	mu.Lock()
	defer mu.Unlock()
	return current.FQDN
}

func Get() Flags {
	mu.Lock()
	defer mu.Unlock()

	return current
}

func (f Flags) AsProto() *proto.Features {
	mu.Lock()
	defer mu.Unlock()
	return &proto.Features{
		Fqdn: &proto.FQDNFeature{
			Enabled: f.FQDN}}
}
