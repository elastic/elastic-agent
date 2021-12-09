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

package process

import "time"

// Config for fine tuning new process
type Config struct {
	SpawnTimeout   time.Duration `yaml:"spawn_timeout" config:"spawn_timeout"`
	StopTimeout    time.Duration `yaml:"stop_timeout" config:"stop_timeout"`
	FailureTimeout time.Duration `yaml:"failure_timeout" config:"failure_timeout"`

	// TODO: cgroups and namespaces
}

// DefaultConfig creates a config with pre-set default values.
func DefaultConfig() *Config {
	return &Config{
		SpawnTimeout:   30 * time.Second,
		StopTimeout:    30 * time.Second,
		FailureTimeout: 10 * time.Second,
	}
}
