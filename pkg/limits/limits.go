// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

	// CPU is the requested CPU limit for the agent and its components together, as a percentage of the host CPU capacity.
	// It accepts a number from 1 to 100. go-ucfg converts numbers and numeric text the same way as for go_max_procs, so a
	// fraction is cut to its whole part. 0 and any value outside 1 to 100 is rejected. No value means the cap is disabled.
	// It is excluded from JSON because components must not receive it.
	CPU CPULimit `config:"cpu" json:"-"`
}

// CPULimit is a cap on CPU use, as a percentage of the host CPU capacity.
// The zero value means no value, so the cap is disabled. A config value of 0 is invalid, so that it is not mistaken for
// "off" or "unlimited".
type CPULimit struct {
	percent int
}

// Unpack implements ucfg.IntUnpacker.
func (l *CPULimit) Unpack(n int64) error {
	if n < 1 || n > 100 {
		return fmt.Errorf("invalid CPU limit %d: must be a whole number from 1 to 100", n)
	}
	l.percent = int(n)
	return nil
}

// Enabled reports whether the cap has a value.
func (l CPULimit) Enabled() bool {
	return l.percent > 0
}

// Percent returns the cap as a percentage from 1 to 100, or 0 when there is no value.
func (l CPULimit) Percent() int {
	return l.percent
}

// The floor keeps a low cap from leaving a small host with too little CPU.
const (
	// cpuFloorPercent is the floor as a percentage of at most cpuFloorMaxCPUs logical CPUs.
	cpuFloorPercent = 5.0
	// cpuFloorMaxCPUs is the largest number of logical CPUs the floor counts.
	cpuFloorMaxCPUs = 32
)

// TargetCPUs returns the number of CPUs the cap asks for, after the floor. The real limit can be lower, for example
// because of a quota on a parent group.
// logicalCPUs is the number of online logical CPUs on the host and must be at least 1.
// The result can be below 1, for example 0.2. It is 0 when the cap is off.
func (l CPULimit) TargetCPUs(logicalCPUs int) float64 {
	if !l.Enabled() {
		return 0
	}
	requested := float64(l.percent) * float64(logicalCPUs) / 100
	floor := cpuFloorPercent * float64(min(logicalCPUs, cpuFloorMaxCPUs)) / 100
	return max(requested, floor)
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
	} else {
		// The other fields did not change, so only the CPU value needs a write.
		f.cfg.CPU = newLimits.CPU
	}
}

// AddLimitsOnChangeCallback takes a callback function that will be called with the new and old values
// of limits when the go_max_procs value changes.
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
	if err := c.UnpackTo(&parsedConfig); err != nil {
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
