// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package common

import (
	"github.com/mitchellh/mapstructure"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

// FakeShipperConfigTLS is basic TLS configuration for a shipper.
type FakeShipperConfigTLS struct {
	CAs  []string `mapstructure:"certificate_authorities"`
	Cert string   `mapstructure:"certificate"`
	Key  string   `mapstructure:"key"`
}

// FakeShipperConfig is basic configuration for a shipper.
type FakeShipperConfig struct {
	Server string                `mapstructure:"server"`
	TLS    *FakeShipperConfigTLS `mapstructure:"ssl"`
}

// ParseFakeShipperConfig parses the shipper GRPC server and ssl configuration information.
func ParseFakeShipperConfig(cfg *proto.UnitExpectedConfig) (FakeShipperConfig, error) {
	var r FakeShipperConfig
	err := mapstructure.Decode(cfg.Source.AsMap(), &r)
	if err != nil {
		return FakeShipperConfig{}, err
	}
	return r, nil
}
