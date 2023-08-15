// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/core/env"
)

// setup configuration

type setupConfig struct {
	Fleet       fleetConfig       `config:"fleet"`
	FleetServer fleetServerConfig `config:"fleet_server"`
	Kibana      kibanaConfig      `config:"kibana"`
}

type fleetConfig struct {
	CA              string        `config:"ca"`
	Enroll          bool          `config:"enroll"`
	EnrollmentToken string        `config:"enrollment_token"`
	Force           bool          `config:"force"`
	Insecure        bool          `config:"insecure"`
	TokenName       string        `config:"token_name"`
	TokenPolicyName string        `config:"token_policy_name"`
	URL             string        `config:"url"`
	DaemonTimeout   time.Duration `config:"daemon_timeout"`
}

type fleetServerConfig struct {
	Cert           string              `config:"cert"`
	CertKey        string              `config:"cert_key"`
	PassphrasePath string              `config:"key_passphrase_path"`
	Elasticsearch  elasticsearchConfig `config:"elasticsearch"`
	Enable         bool                `config:"enable"`
	Host           string              `config:"host"`
	InsecureHTTP   bool                `config:"insecure_http"`
	PolicyID       string              `config:"policy_id"`
	Port           string              `config:"port"`
	Headers        map[string]string   `config:"headers"`
	Timeout        time.Duration       `config:"timeout"`
}

type elasticsearchConfig struct {
	CA                   string `config:"ca"`
	CATrustedFingerprint string `config:"ca_trusted_fingerprint"`
	Host                 string `config:"host"`
	ServiceToken         string `config:"service_token"`
	ServiceTokenPath     string `config:"service_token_path"`
	Insecure             bool   `config:"insecure"`
}

type kibanaConfig struct {
	Fleet              kibanaFleetConfig `config:"fleet"`
	RetrySleepDuration time.Duration     `config:"retry_sleep_duration"`
	RetryMaxCount      int               `config:"retry_max_count"`
	Headers            map[string]string `config:"headers"`
}

type kibanaFleetConfig struct {
	CA               string `config:"ca"`
	Host             string `config:"host"`
	Username         string `config:"username"`
	Password         string `config:"password"`
	ServiceToken     string `config:"service_token"`
	ServiceTokenPath string `config:"service_token_path"`
}

func defaultAccessConfig() (setupConfig, error) {
	retrySleepDuration, err := env.DurationWithDefault(defaultRequestRetrySleep, requestRetrySleepEnv)
	if err != nil {
		return setupConfig{}, err
	}

	retryMaxCount, err := env.IntWithDefault(defaultMaxRequestRetries, maxRequestRetriesEnv)
	if err != nil {
		return setupConfig{}, err
	}

	cfg := setupConfig{
		Fleet: fleetConfig{
			CA:              env.WithDefault("", "FLEET_CA", "KIBANA_CA", "ELASTICSEARCH_CA"),
			Enroll:          env.Bool("FLEET_ENROLL", "FLEET_SERVER_ENABLE"),
			EnrollmentToken: env.WithDefault("", "FLEET_ENROLLMENT_TOKEN"),
			Force:           env.Bool("FLEET_FORCE"),
			Insecure:        env.Bool("FLEET_INSECURE"),
			TokenName:       env.WithDefault("Default", "FLEET_TOKEN_NAME"),
			TokenPolicyName: env.WithDefault("", "FLEET_TOKEN_POLICY_NAME"),
			URL:             env.WithDefault("", "FLEET_URL"),
			DaemonTimeout:   env.Timeout("FLEET_DAEMON_TIMEOUT"),
		},
		FleetServer: fleetServerConfig{
			Cert:           env.WithDefault("", "FLEET_SERVER_CERT"),
			CertKey:        env.WithDefault("", "FLEET_SERVER_CERT_KEY"),
			PassphrasePath: env.WithDefault("", "FLEET_SERVER_CERT_KEY_PASSPHRASE"),
			Elasticsearch: elasticsearchConfig{
				Host:                 env.WithDefault("http://elasticsearch:9200", "FLEET_SERVER_ELASTICSEARCH_HOST", "ELASTICSEARCH_HOST"),
				ServiceToken:         env.WithDefault("", "FLEET_SERVER_SERVICE_TOKEN"),
				ServiceTokenPath:     env.WithDefault("", "FLEET_SERVER_SERVICE_TOKEN_PATH"),
				CA:                   env.WithDefault("", "FLEET_SERVER_ELASTICSEARCH_CA", "ELASTICSEARCH_CA"),
				CATrustedFingerprint: env.WithDefault("", "FLEET_SERVER_ELASTICSEARCH_CA_TRUSTED_FINGERPRINT"),
				Insecure:             env.Bool("FLEET_SERVER_ELASTICSEARCH_INSECURE"),
			},
			Enable:       env.Bool("FLEET_SERVER_ENABLE"),
			Host:         env.WithDefault("", "FLEET_SERVER_HOST"),
			InsecureHTTP: env.Bool("FLEET_SERVER_INSECURE_HTTP"),
			PolicyID:     env.WithDefault("", "FLEET_SERVER_POLICY_ID", "FLEET_SERVER_POLICY"),
			Port:         env.WithDefault("", "FLEET_SERVER_PORT"),
			Headers:      env.Map("FLEET_HEADER"),
			Timeout:      env.Timeout("FLEET_SERVER_TIMEOUT"),
		},
		Kibana: kibanaConfig{
			Fleet: kibanaFleetConfig{
				Host:             env.WithDefault("http://kibana:5601", "KIBANA_FLEET_HOST", "KIBANA_HOST"),
				Username:         env.WithDefault("elastic", "KIBANA_FLEET_USERNAME", "KIBANA_USERNAME", "ELASTICSEARCH_USERNAME"),
				Password:         env.WithDefault("changeme", "KIBANA_FLEET_PASSWORD", "KIBANA_PASSWORD", "ELASTICSEARCH_PASSWORD"),
				ServiceToken:     env.WithDefault("", "KIBANA_FLEET_SERVICE_TOKEN", "FLEET_SERVER_SERVICE_TOKEN"),
				ServiceTokenPath: env.WithDefault("", "KIBANA_FLEET_SERVICE_TOKEN_PATH", "FLEET_SERVER_SERVICE_TOKEN_PATH"),
				CA:               env.WithDefault("", "KIBANA_FLEET_CA", "KIBANA_CA", "ELASTICSEARCH_CA"),
			},
			RetrySleepDuration: retrySleepDuration,
			RetryMaxCount:      retryMaxCount,
			Headers:            env.Map("FLEET_KIBANA_HEADER"),
		},
	}
	return cfg, nil
}
