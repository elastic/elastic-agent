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
