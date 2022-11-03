package common

import (
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/mitchellh/mapstructure"
)

type FakeShipperConfigTLS struct {
	CAs  []string `mapstructure:"certificate_authorities"`
	Cert string   `mapstructure:"certificate"`
	Key  string   `mapstructure:"key"`
}

type FakeShipperConfig struct {
	Server string                `mapstructure:"server"`
	TLS    *FakeShipperConfigTLS `mapstructure:"ssl"`
}

func ParseFakeShipperConfig(cfg *proto.UnitExpectedConfig) (FakeShipperConfig, error) {
	var r FakeShipperConfig
	err := mapstructure.Decode(cfg.Source, &r)
	if err != nil {
		return FakeShipperConfig{}, err
	}
	return r, nil
}
