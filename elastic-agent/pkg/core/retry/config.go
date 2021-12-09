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

package retry

import "time"

const (
	defaultRetriesCount = 3
	defaultDelay        = 30 * time.Second
	defaultMaxDelay     = 5 * time.Minute
)

// Config is a configuration of a strategy
type Config struct {
	// Enabled determines whether retry is possible. Default is false.
	Enabled bool `yaml:"enabled" config:"enabled"`
	// RetriesCount specifies number of retries. Default is 3.
	// Retry count of 1 means it will be retried one time after one failure.
	RetriesCount int `yaml:"retriesCount" config:"retriesCount"`
	// Delay specifies delay in ms between retries. Default is 30s
	Delay time.Duration `yaml:"delay" config:"delay"`
	// MaxDelay specifies maximum delay in ms between retries. Default is 300s (5min)
	MaxDelay time.Duration `yaml:"maxDelay" config:"maxDelay"`
	// Exponential determines whether delay is treated as exponential.
	// With 30s delay and 3 retries: 30, 60, 120s
	// Default is false
	Exponential bool `yaml:"exponential" config:"exponential"`
}

// DefaultConfig creates a config with pre-set default values.
func DefaultConfig() *Config {
	return &Config{
		Enabled:      false,
		RetriesCount: 3,
		Delay:        30 * time.Second,
		MaxDelay:     5 * time.Minute,
		Exponential:  false,
	}
}
