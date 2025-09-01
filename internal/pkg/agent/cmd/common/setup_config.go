// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import "time"

// setup configuration

type SetupConfig struct {
	Fleet       FleetConfig       `config:"fleet"`
	FleetServer FleetServerConfig `config:"fleet_server"`
	Kibana      KibanaConfig      `config:"kibana"`
}

type FleetConfig struct {
	CA              string            `config:"ca"`
	Enroll          bool              `config:"enroll"`
	EnrollmentToken string            `config:"enrollment_token"`
	ID              string            `config:"id"`
	ReplaceToken    string            `config:"replace_token"`
	Force           bool              `config:"force"`
	Insecure        bool              `config:"insecure"`
	TokenName       string            `config:"token_name"`
	TokenPolicyName string            `config:"token_policy_name"`
	URL             string            `config:"url"`
	Headers         map[string]string `config:"headers"`
	DaemonTimeout   time.Duration     `config:"daemon_timeout"`
	EnrollTimeout   time.Duration     `config:"enroll_timeout"`
	Cert            string            `config:"cert"`
	CertKey         string            `config:"cert_key"`
}

type FleetServerConfig struct {
	Cert           string              `config:"cert"`
	CertKey        string              `config:"cert_key"`
	PassphrasePath string              `config:"key_passphrase_path"`
	ClientAuth     string              `config:"client_authentication"`
	Elasticsearch  ElasticsearchConfig `config:"elasticsearch"`
	Enable         bool                `config:"enable"`
	Host           string              `config:"host"`
	InsecureHTTP   bool                `config:"insecure_http"`
	PolicyID       string              `config:"policy_id"`
	Port           string              `config:"port"`
	Headers        map[string]string   `config:"headers"`
	Timeout        time.Duration       `config:"timeout"`
}

type ElasticsearchConfig struct {
	CA                   string `config:"ca"`
	CATrustedFingerprint string `config:"ca_trusted_fingerprint"`
	Host                 string `config:"host"`
	ServiceToken         string `config:"service_token"`
	ServiceTokenPath     string `config:"service_token_path"`
	Insecure             bool   `config:"insecure"`
	Cert                 string `config:"cert"`
	CertKey              string `config:"cert_key"`
}

type KibanaConfig struct {
	Fleet              KibanaFleetConfig `config:"fleet"`
	RetrySleepDuration time.Duration     `config:"retry_sleep_duration"`
	RetryMaxCount      int               `config:"retry_max_count"`
	Headers            map[string]string `config:"headers"`
}

type KibanaFleetConfig struct {
	CA               string `config:"ca"`
	Host             string `config:"host"`
	Username         string `config:"username"`
	Password         string `config:"password"`
	ServiceToken     string `config:"service_token"`
	ServiceTokenPath string `config:"service_token_path"`
}
