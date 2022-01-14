// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package configuration

import (
	"time"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
)

var (
	// ErrInvalidPeriod is returned when a reload period interval is not valid
	ErrInvalidPeriod = errors.New("period must be higher than zero")
)

// ReloadConfig defines behavior of a reloader for standalone configuration.
type ReloadConfig struct {
	Enabled bool          `config:"enabled" yaml:"enabled"`
	Period  time.Duration `config:"period" yaml:"period"`
}

// Validate validates settings of configuration.
func (r *ReloadConfig) Validate() error {
	if r.Enabled {
		if r.Period <= 0 {
			return ErrInvalidPeriod
		}
	}
	return nil
}

// DefaultReloadConfig creates a default configuration for standalone mode.
func DefaultReloadConfig() *ReloadConfig {
	return &ReloadConfig{
		Enabled: true,
		Period:  10 * time.Second,
	}
}
