// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import "time"

const defaultPort = 6791
const defaultNamespace = "default"

// MonitoringConfig describes a configuration of a monitoring
type MonitoringConfig struct {
	Enabled        bool                  `yaml:"enabled" config:"enabled"`
	MonitorLogs    bool                  `yaml:"logs" config:"logs"`
	MonitorMetrics bool                  `yaml:"metrics" config:"metrics"`
	LogMetrics     bool                  `yaml:"-" config:"-"`
	HTTP           *MonitoringHTTPConfig `yaml:"http" config:"http"`
	Namespace      string                `yaml:"namespace" config:"namespace"`
	Pprof          *PprofConfig          `yaml:"pprof" config:"pprof"`
	MonitorTraces  bool                  `yaml:"traces" config:"traces"`
	APM            APMConfig             `yaml:"apm,omitempty" config:"apm,omitempty" json:"apm,omitempty"`
	Diagnostics    Diagnostics           `yaml:"diagnostics,omitempty" json:"diagnostics,omitempty"`
}

// MonitoringHTTPConfig is a config defining HTTP endpoint published by agent
// for other processes to watch its metrics.
// Processes are only exposed when HTTP is enabled.
type MonitoringHTTPConfig struct {
	Enabled bool          `yaml:"enabled" config:"enabled"`
	Host    string        `yaml:"host" config:"host"`
	Port    int           `yaml:"port" config:"port" validate:"min=0,max=65535,nonzero"`
	Buffer  *BufferConfig `yaml:"buffer" config:"buffer"`
}

// PprofConfig is a struct for the pprof enablement flag.
// It is a nil struct by default to allow the agent to use the a value that the user has injected into fleet.yml as the source of truth that is passed to beats
// TODO get this value from Kibana?
type PprofConfig struct {
	Enabled bool `yaml:"enabled" config:"enabled"`
}

// BufferConfig is a struct for for the metrics buffer endpoint
type BufferConfig struct {
	Enabled bool `yaml:"enabled" config:"enabled"`
}

// DefaultConfig creates a config with pre-set default values.
func DefaultConfig() *MonitoringConfig {
	return &MonitoringConfig{
		Enabled:        true,
		MonitorLogs:    true,
		MonitorMetrics: true,
		LogMetrics:     true,
		MonitorTraces:  false,
		HTTP: &MonitoringHTTPConfig{
			Enabled: false,
			Host:    "localhost",
			Port:    defaultPort,
		},
		Namespace:   defaultNamespace,
		APM:         defaultAPMConfig(),
		Diagnostics: defaultDiagnostics(),
	}
}

// APMConfig configures APM Tracing.
type APMConfig struct {
	Environment  string   `config:"environment"`
	APIKey       string   `config:"api_key"`
	SecretToken  string   `config:"secret_token"`
	Hosts        []string `config:"hosts"`
	GlobalLabels string   `config:"global_labels"`
	TLS          APMTLS   `config:"tls"`
}

// APMTLS contains the configuration options necessary for configuring TLS in
// apm-agent-go.
type APMTLS struct {
	SkipVerify        bool   `config:"skip_verify"`
	ServerCertificate string `config:"server_certificate"`
	ServerCA          string `config:"server_ca"`
}

func defaultAPMConfig() APMConfig {
	return APMConfig{}
}

// Uploader contains the configuration for retries when uploading a file (diagnostics bundle) to fleet-server.
type Uploader struct {
	MaxRetries int           `config:"max_retries"`
	InitDur    time.Duration `config:"init_duration"`
	MaxDur     time.Duration `config:"max_duration"`
}

func defaultUploader() Uploader {
	return Uploader{
		MaxRetries: 10,
		InitDur:    time.Second,
		MaxDur:     time.Minute * 10,
	}
}

// Limit contains the configuration for rate-limiting operations
type Limit struct {
	Interval time.Duration `config:"interval"`
	Burst    int           `config:"burst"`
}

func defaultLimit() Limit {
	return Limit{
		Interval: time.Minute,
		Burst:    1,
	}
}

// Diagnostics contains the configuration needed to configure the diagnostics handler.
type Diagnostics struct {
	Uploader Uploader `config:"uploader"`
	Limit    Limit    `config:"limit"`
}

func defaultDiagnostics() Diagnostics {
	return Diagnostics{
		Uploader: defaultUploader(),
		Limit:    defaultLimit(),
	}
}
