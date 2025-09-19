package elasticdiagnosticsextension

import (
	"errors"

	"go.opentelemetry.io/collector/component"
)

type Config struct {
	Host    string `mapstructure:"host"`
	Network string `mapstructure:"network"`
}

func createDefaultConfig() component.Config {
	return &Config{
		Network: "unix",
	}
}

func (c *Config) Validate() error {
	if c.Host == "" {
		return errors.New("hosts is a required field")
	}
	return nil
}
