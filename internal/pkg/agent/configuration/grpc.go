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
	Port                    uint16 `config:"port"` // [gRPC:8.15] Change to int32 instead of uint16, when Endpoint is ready for local gRPC
	MaxMsgSize              int    `config:"max_message_size"`
	CheckinChunkingDisabled bool   `config:"checkin_chunking_disabled"`
}

// DefaultGRPCConfig creates a default server configuration.
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		Address: "localhost",
		// [gRPC:8.15] The line below is commented out for 8.14 and should replace the current port default once Endpoint is ready for domain socket gRPC
		// Port:    -1, // -1 (negative) port value by default enabled "local" rpc utilizing domain sockets and named pipes
		Port:                    6789,              // Set TCP gRPC by default
		MaxMsgSize:              1024 * 1024 * 100, // grpc default 4MB is unsufficient for diagnostics
		CheckinChunkingDisabled: false,             // on by default
	}
}

// String returns the composed listen address for the GRPC.
func (cfg *GRPCConfig) String() string {
	return fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
}

// IsLocal returns true if port value is less than 0
func (cfg *GRPCConfig) IsLocal() bool {
	// [gRPC:8.15] Use the commented implementation once Endpoint is ready for local gRPC
	// return cfg.Port < 0
	return false
}
