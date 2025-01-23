// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"fmt"
	"os"
	"strconv"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const (
	// DefaultGRPCPort is the default non-zero port in most situations. Ideally we'd always bind to
	// port 0 to avoid collisions with other Elastic Agents or applications, but this would be a
	// breaking change for users that have to manually whitelist the gRPC port in local firewall rules.
	DefaultGRPCPort = uint16(6789)

	// DefaultGRPCPortInInstallNamespace is the port used when explicitly installed in an installation
	// namespace to allow multiple Elastic Agents on the same machine. Must be zero to avoid collisions.
	DefaultGRPCPortInInstallNamespace = uint16(0)

	// DefaultGPRCPortInContainer is the port used in a container. Defaults to zero to allow use of
	// host networking (hostNetwork: true) in Kubernetes without port collisions between pods.
	DefaultGPRCPortInContainer = uint16(0)

	// grpcPortContainerEnvVar is the environment variable allowing containers to specify a fixed port.
	grpcPortContainerEnvVar = "ELASTIC_AGENT_GRPC_PORT"
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
	defaultPort := DefaultGRPCPort
	if paths.InInstallNamespace() {
		defaultPort = DefaultGRPCPortInInstallNamespace
	}

	return &GRPCConfig{
		Address:                 "localhost",
		Port:                    defaultPort,
		MaxMsgSize:              1024 * 1024 * 100, // grpc default 4MB is unsufficient for diagnostics
		CheckinChunkingDisabled: false,             // on by default
	}
}

// OverrideDefaultContainerGRPCPort is the configuration override used by the container command
// to switch to a more convenient default port.
func OverrideDefaultContainerGRPCPort(cfg *GRPCConfig) {
	cfg.Port = DefaultGPRCPortInContainer

	// Allow manually specifying the port via an undocumented environment variable in case
	// the change from the original DefaultGRPCPort causes unexpected problems.
	grpcPortEnv, ok := os.LookupEnv(grpcPortContainerEnvVar)
	if ok {
		port, err := strconv.Atoi(grpcPortEnv)
		if err == nil {
			cfg.Port = uint16(port)
		}
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
