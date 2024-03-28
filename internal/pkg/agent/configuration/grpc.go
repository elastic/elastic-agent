// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"fmt"
)

// GRPCConfig is a configuration of GRPC server.
type GRPCConfig struct {
	Address                 string `config:"address"`
	Port                    uint16 `config:"port"`
	MaxMsgSize              int    `config:"max_message_size"`
	CheckinChunkingDisabled bool   `config:"checkin_chunking_disabled"`
	Local                   bool   `config:"local"` // Enables RPC via domain socker/named pipe
}

// DefaultGRPCConfig creates a default server configuration.
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		Address:                 "localhost",
		Port:                    6789,
		MaxMsgSize:              1024 * 1024 * 100, // grpc default 4MB is unsufficient for diagnostics
		CheckinChunkingDisabled: false,             // on by default
		Local:                   false,             // Use IP port grpc by default
	}
}

// String returns the composed listen address for the GRPC.
func (cfg *GRPCConfig) String() string {
	return fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
}
