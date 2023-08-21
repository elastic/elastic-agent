// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limits

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

var (
	current = limits{
		cfg: LimitsConfig{
			GoMaxProcs: 0, // means GOMAXPROCS is set to the CPU count.
		},
	}
)

type rootConfig struct {
	Agent agentConfig `json:"agent" yaml:"agent" config:"agent"`
}

type agentConfig struct {
	Limits LimitsConfig `json:"limits" yaml:"limits" config:"limits"`
}

type LimitsConfig struct {
	// GoMaxProcs limits the number of operating system threads that can execute user-level Go code simultaneously.
	// Translates into the GOMAXPROCS runtime parameter for each Go process started by the agent and the agent itself.
	// By default is set to `0` which means using all available CPUs.
	GoMaxProcs int `yaml:"go_max_procs" config:"go_max_procs" json:"go_max_procs"`
}

type LimitsOnChangeCallback func(new, old LimitsConfig)

// this struct exists only for grouping variables, it's a singleton
type limits struct {
	mu        sync.RWMutex
	cfg       LimitsConfig
	callbacks map[string]LimitsOnChangeCallback
}

// setGoMaxProcs sets the value of the GoMaxProcs limit.
// if the value is 0, it's reset to default (count of available CPUs).
func (f *limits) set(newLimits *LimitsConfig) {
	if newLimits == nil {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	oldLimits := f.cfg
	changed := false

	// calling `runtime.GOMAXPROCS` is expensive, so we call it only when the value really changed
	if newLimits.GoMaxProcs != oldLimits.GoMaxProcs {
		if newLimits.GoMaxProcs == 0 {
			_ = runtime.GOMAXPROCS(runtime.NumCPU())
		} else {
			_ = runtime.GOMAXPROCS(newLimits.GoMaxProcs)
		}
		changed = true
	}

	if changed {
		f.cfg = *newLimits
		for _, cb := range f.callbacks {
			cb(f.cfg, oldLimits)
		}
	}
}

// AddLimitsOnChangeCallback takes a callback function that will be called with the new and old values
// of limits whenever they change.
// It also takes a string ID which is used in `RemoveLimitsOnChangeCallback` to de-register the callback.
func AddLimitsOnChangeCallback(cb LimitsOnChangeCallback, id string) {
	current.mu.Lock()
	defer current.mu.Unlock()

	// Initialize callbacks map if necessary.
	if current.callbacks == nil {
		current.callbacks = map[string]LimitsOnChangeCallback{}
	}

	current.callbacks[id] = cb
}

// RemoveLimitsOnChangeCallback removes the callback function associated with the given ID
// (originally passed to `AddLimitsOnChangeCallback`).
func RemoveLimitsOnChangeCallback(id string) {
	current.mu.Lock()
	defer current.mu.Unlock()

	delete(current.callbacks, id)
}

// Parse receives a policy, parses and returns the limits section.
// policy can be a *config.Config, config.Config or anything config.NewConfigFrom
// can work with. If policy is nil, Parse is a no-op.
func Parse(policy any) (*LimitsConfig, error) {
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

	parsedConfig := rootConfig{}
	if err := c.Unpack(&parsedConfig); err != nil {
		return nil, fmt.Errorf("could not unpack limits config: %w", err)
	}

	return &parsedConfig.Agent.Limits, nil
}

// Apply receives a config and applies it. If c is nil, Apply is a no-op.
func Apply(c *config.Config) error {
	if c == nil {
		return nil
	}

	var err error

	parsedLimits, err := Parse(c)
	if err != nil {
		return fmt.Errorf("could not apply limits config: %w", err)
	}

	current.set(parsedLimits)

	return nil
}

// GoMaxProcs reports the currently stored limit on the number of operating system threads per process in Go.
// It's possible that the returned value does not reflect the real `runtime.GOMAXPROCS` in case it's been set elsewhere.
func GoMaxProcs() int {
	return current.cfg.GoMaxProcs
}
