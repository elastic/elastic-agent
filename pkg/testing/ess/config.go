// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

// GetESSAPIKey returns the ESS API key, if it exists
func GetESSAPIKey() (string, bool, error) {
	essAPIKeyFile, err := GetESSAPIKeyFilePath()
	if err != nil {
		return "", false, err
	}
	_, err = os.Stat(essAPIKeyFile)
	if os.IsNotExist(err) {
		return "", false, nil
	} else if err != nil {
		return "", false, fmt.Errorf("unable to check if ESS config directory exists: %w", err)
	}
	data, err := os.ReadFile(essAPIKeyFile)
	if err != nil {
		return "", true, fmt.Errorf("unable to read ESS API key: %w", err)
	}
	essAPIKey := strings.TrimSpace(string(data))
	return essAPIKey, true, nil
}

// GetESSAPIKeyFilePath returns the path to the ESS API key file
func GetESSAPIKeyFilePath() (string, error) {
	essAPIKeyFile := os.Getenv("TEST_INTEG_AUTH_ESS_APIKEY_FILE")
	if essAPIKeyFile == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("unable to determine user's home directory: %w", err)
		}
		essAPIKeyFile = filepath.Join(homeDir, ".config", "ess", "api_key.txt")
	}
	return essAPIKeyFile, nil
}
