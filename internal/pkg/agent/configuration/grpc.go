// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import "fmt"

// GRPCConfig is a configuration of GRPC server.
type GRPCConfig struct {
	Address string `config:"address"`
	Port    uint16 `config:"port"`
}

// DefaultGRPCConfig creates a default server configuration.
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		Address: "localhost",
		Port:    6789,
	}
}

// String returns the composed listen address for the GRPC.
func (cfg *GRPCConfig) String() string {
	return fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
}
