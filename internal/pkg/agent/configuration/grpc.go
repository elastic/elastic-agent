// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// GRPCConfig is a configuration of GRPC server.
type GRPCConfig struct {
	Address                 string `config:"address"`
	Port                    uint16 `config:"port"`
	MaxMsgSize              int    `config:"max_message_size"`
	CheckinChunkingDisabled bool   `config:"checkin_chunking_disabled"`
}

// DefaultGRPCConfig creates a default server configuration.
func DefaultGRPCConfig() *GRPCConfig {
	// In development mode bind to port zero to select a random free port to avoid collisions with
	// any already installed Elastic Agent. Ideally we'd always bind to port zero, but this would be
	// breaking for users that had to manually whitelist the gRPC port in local firewall rules.
	defaultPort := uint16(6789)
	if paths.IsDevelopmentMode() {
		defaultPort = 0
	}

	return &GRPCConfig{
		Address:                 "localhost",
		Port:                    defaultPort,
		MaxMsgSize:              1024 * 1024 * 100, // grpc default 4MB is unsufficient for diagnostics
		CheckinChunkingDisabled: false,             // on by default
	}
}

// String returns the composed listen address for the GRPC.
func (cfg *GRPCConfig) String() string {
	return fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
}
