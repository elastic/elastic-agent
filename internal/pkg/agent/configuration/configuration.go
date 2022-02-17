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
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

// Configuration is a overall agent configuration
type Configuration struct {
	Fleet    *FleetAgentConfig `config:"fleet"  yaml:"fleet" json:"fleet"`
	Settings *SettingsConfig   `config:"agent"  yaml:"agent" json:"agent"`
}

// DefaultConfiguration creates a configuration prepopulated with default values.
func DefaultConfiguration() *Configuration {
	return &Configuration{
		Fleet:    DefaultFleetAgentConfig(),
		Settings: DefaultSettingsConfig(),
	}
}

// NewFromConfig creates a configuration based on common Config.
func NewFromConfig(cfg *config.Config) (*Configuration, error) {
	c := DefaultConfiguration()
	if err := cfg.Unpack(c); err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}

	return c, nil
}

// NewFromFile uses unencrypted disk store to load a configuration.
func NewFromFile(path string) (*Configuration, error) {
	store := storage.NewDiskStore(path)
	reader, err := store.Load()
	if err != nil {
		return nil, errors.New(err, "could not initialize config store",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	config, err := config.NewConfigFrom(reader)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("fail to read configuration %s for the elastic-agent", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	return NewFromConfig(config)
}

// AgentInfo is a set of agent information.
type AgentInfo struct {
	ID string `json:"id" yaml:"id" config:"id"`
}
