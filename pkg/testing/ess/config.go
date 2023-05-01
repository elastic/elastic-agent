// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

type Config struct {
	BaseUrl string `json:"base_url" yaml:"base_url"`
	ApiKey  string `json:"api_key" yaml:"api_key"`
}

func defaultConfig() *Config {
	return &Config{
		BaseUrl: `https://console.qa.cld.elstc.co/api/v1`,
	}
}

// Merge overlays the provided configuration on top of
// this configuration.
func (c *Config) Merge(anotherConfig Config) {
	if anotherConfig.BaseUrl != "" {
		c.BaseUrl = anotherConfig.BaseUrl
	}

	if anotherConfig.ApiKey != "" {
		c.ApiKey = anotherConfig.ApiKey
	}
}
