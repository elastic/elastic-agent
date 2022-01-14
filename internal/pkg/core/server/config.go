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

package server

import (
	"fmt"

	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
)

// Config is a configuration of GRPC server.
type Config struct {
	Address string `config:"address"`
	Port    uint16 `config:"port"`
}

// DefaultGRPCConfig creates a default server configuration.
func DefaultGRPCConfig() *Config {
	return &Config{
		Address: "localhost",
		Port:    6789,
	}
}

// NewFromConfig creates a new GRPC server for clients to connect to.
func NewFromConfig(logger *logger.Logger, cfg *Config, handler Handler) (*Server, error) {
	return New(logger, fmt.Sprintf("%s:%d", cfg.Address, cfg.Port), handler)
}
