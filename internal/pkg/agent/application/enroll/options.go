// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package enroll

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// EnrollOptions define all the supported enrollment option.
type EnrollOptions struct {
	URL                  string                     `yaml:"url,omitempty" json:"url,omitempty"`
	InternalURL          string                     `yaml:"-" json:"-"`
	CAs                  []string                   `yaml:"ca,omitempty" json:"ca,omitempty"`
	CASha256             []string                   `yaml:"ca_sha256,omitempty" json:"ca_sha256,omitempty"`
	Certificate          string                     `yaml:"certificate,omitempty" json:"certificate,omitempty"`
	Key                  string                     `yaml:"key,omitempty" json:"key,omitempty"`
	KeyPassphrasePath    string                     `yaml:"key_passphrase_path,omitempty" json:"key_passphrase_path,omitempty"`
	Insecure             bool                       `yaml:"insecure,omitempty" json:"insecure,omitempty"`
	ID                   string                     `yaml:"id,omitempty" json:"id,omitempty"`
	ReplaceToken         string                     `yaml:"replace_token,omitempty" json:"replace_token,omitempty"`
	EnrollAPIKey         string                     `yaml:"enrollment_key,omitempty" json:"enrollment_key,omitempty"`
	Staging              string                     `yaml:"staging,omitempty" json:"staging,omitempty"`
	ProxyURL             string                     `yaml:"proxy_url,omitempty" json:"proxy_url,omitempty"`
	ProxyDisabled        bool                       `yaml:"proxy_disabled,omitempty" json:"proxy_disabled,omitempty"`
	ProxyHeaders         map[string]string          `yaml:"proxy_headers,omitempty" json:"proxy_headers,omitempty"`
	DaemonTimeout        time.Duration              `yaml:"daemon_timeout,omitempty" json:"daemon_timeout,omitempty"`
	UserProvidedMetadata map[string]interface{}     `yaml:"-" json:"-"`
	FixPermissions       *utils.FileOwner           `yaml:"-" json:"-"`
	DelayEnroll          bool                       `yaml:"-" json:"-"`
	FleetServer          EnrollCmdFleetServerOption `yaml:"-" json:"-"`
	SkipCreateSecret     bool                       `yaml:"-" json:"-"`
	SkipDaemonRestart    bool                       `yaml:"-" json:"-"`
	Tags                 []string                   `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// EnrollCmdFleetServerOption define all the supported enrollment options for bootstrapping with Fleet Server.
type EnrollCmdFleetServerOption struct {
	ConnStr               string
	ElasticsearchCA       string
	ElasticsearchCASHA256 string
	ElasticsearchInsecure bool
	ElasticsearchCert     string
	ElasticsearchCertKey  string
	ServiceToken          string
	ServiceTokenPath      string
	PolicyID              string
	Host                  string
	Port                  uint16
	InternalPort          uint16
	Cert                  string
	CertKey               string
	CertKeyPassphrasePath string
	ClientAuth            string
	Insecure              bool
	SpawnAgent            bool
	Headers               map[string]string
	Timeout               time.Duration
}

// remoteConfig returns the configuration used to connect the agent to a fleet process.
func (e *EnrollOptions) RemoteConfig(failOnInsecureMismatch bool) (remote.Config, error) {
	cfg, err := remote.NewConfigFromURL(e.URL)
	if err != nil {
		return remote.Config{}, err
	}
	if failOnInsecureMismatch && cfg.Protocol == remote.ProtocolHTTP && !e.Insecure {
		return remote.Config{}, fmt.Errorf("connection to fleet-server is insecure, strongly recommended to use a secure connection (override with --insecure)")
	}

	var tlsCfg tlscommon.Config

	// Add any SSL options from the CLI.
	if len(e.CAs) > 0 || len(e.CASha256) > 0 {
		tlsCfg.CAs = e.CAs
		tlsCfg.CASha256 = e.CASha256
	}
	if e.Insecure {
		tlsCfg.VerificationMode = tlscommon.VerifyNone
	}
	if e.Certificate != "" || e.Key != "" {
		tlsCfg.Certificate = tlscommon.CertificateConfig{
			Certificate:    e.Certificate,
			Key:            e.Key,
			PassphrasePath: e.KeyPassphrasePath,
		}
	}

	cfg.Transport.TLS = &tlsCfg

	proxySettings, err := httpcommon.NewHTTPClientProxySettings(e.ProxyURL, e.ProxyHeaders, e.ProxyDisabled)
	if err != nil {
		return remote.Config{}, err
	}

	cfg.Transport.Proxy = *proxySettings

	if e.FleetServer.ConnStr != "" {
		// Ensure that the agent does not use a proxy configuration
		// when connecting to the local fleet server.
		// Note that when running fleet-server the enroll request will be sent to :8220,
		// however when the agent is running afterward requests will be sent to :8221
		cfg.Transport.Proxy.Disable = true
	}

	return cfg, nil
}

func MergeOptionsWithMigrateAction(action *fleetapi.ActionMigrate, options EnrollOptions) (EnrollOptions, error) {
	// there is place to make this much more performant but as this is far away from hot path
	// i'm keeping it this way (michal)
	if action.Data.EnrollmentToken == "" ||
		action.Data.TargetURI == "" {
		return EnrollOptions{}, fmt.Errorf("required fields missing")
	}

	configMap := make(map[string]interface{})

	data, err := json.Marshal(options)
	if err != nil {
		return EnrollOptions{}, fmt.Errorf("failed to encode enroll options: %w", err)
	}

	if err := json.Unmarshal(data, &configMap); err != nil {
		return EnrollOptions{}, fmt.Errorf("failed to decode enroll options: %w", err)
	}

	// overwriting what's needed
	if len(action.Data.Settings) > 0 {
		if err := json.Unmarshal(action.Data.Settings, &configMap); err != nil {
			return EnrollOptions{}, fmt.Errorf("failed to decode migrate setting: %w", err)
		}

	}

	cmBytes, err := json.Marshal(configMap)
	if err != nil {
		return EnrollOptions{}, fmt.Errorf("failed to encode merged migrate setting: %w", err)
	}

	if err := json.Unmarshal(cmBytes, &options); err != nil {
		return EnrollOptions{}, fmt.Errorf("failed to decode merged migrate setting: %w", err)
	}

	options.EnrollAPIKey = action.Data.EnrollmentToken
	options.URL = action.Data.TargetURI

	return options, nil
}

func FromFleetConfig(cfg *configuration.FleetAgentConfig) EnrollOptions {
	options := EnrollOptions{
		EnrollAPIKey:  cfg.AccessAPIKey,
		URL:           cfg.Client.Host,
		ProxyDisabled: cfg.Client.Transport.Proxy.Disable,
		ProxyHeaders:  cfg.Client.Transport.Proxy.Headers,
	}

	if cfg.Client.Transport.TLS != nil {
		options.CAs = cfg.Client.Transport.TLS.CAs
		options.CASha256 = cfg.Client.Transport.TLS.CASha256

		options.Certificate = cfg.Client.Transport.TLS.Certificate.Certificate
		options.Key = cfg.Client.Transport.TLS.Certificate.Key
		options.KeyPassphrasePath = cfg.Client.Transport.TLS.Certificate.PassphrasePath

		options.Insecure = cfg.Client.Transport.TLS.VerificationMode == tlscommon.VerifyNone
	}

	if cfg.Client.Transport.Proxy.URL != nil {
		options.ProxyURL = cfg.Client.Transport.Proxy.URL.String()
	}

	if cfg.Info != nil {
		options.ID = cfg.Info.ID
	}

	return options
}
