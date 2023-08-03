// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

var (
	// ErrInvalidMaxProcs is returned when a MaxProcs is invalid
	ErrInvalidMaxProcs = errors.New("MaxProcs must be higher than zero")
)

type LimitsConfig struct {
	// limits the number of operating system threads per process.
	// For Go processes it translates into GOMAXPROCS, for other platforms it can differ.
	// The agent sets it for itself and sends this value to all components via the control protocol.
	// It's up to the components to handle this value.
	MaxProcs int `yaml:"max_procs" config:"max_procs" json:"max_procs"`
}

// Validate validates settings of the limits configuration.
func (r *LimitsConfig) Validate() error {
	if r.MaxProcs <= 0 {
		return ErrInvalidMaxProcs
	}
	return nil
}

func DefaultLimitsConfig() *LimitsConfig {
	return &LimitsConfig{
		MaxProcs: runtime.NumCPU(),
	}
}
