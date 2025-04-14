// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package enroll

import (
	"fmt"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// EnrollOptions define all the supported enrollment option.
type EnrollOptions struct {
	URL                  string                     `yaml:"url,omitempty"`
	InternalURL          string                     `yaml:"-"`
	CAs                  []string                   `yaml:"ca,omitempty"`
	CASha256             []string                   `yaml:"ca_sha256,omitempty"`
	Certificate          string                     `yaml:"certificate,omitempty"`
	Key                  string                     `yaml:"key,omitempty"`
	KeyPassphrasePath    string                     `yaml:"key_passphrase_path,omitempty"`
	Insecure             bool                       `yaml:"insecure,omitempty"`
	ID                   string                     `yaml:"id,omitempty"`
	ReplaceToken         string                     `yaml:"replace_token,omitempty"`
	EnrollAPIKey         string                     `yaml:"enrollment_key,omitempty"`
	Staging              string                     `yaml:"staging,omitempty"`
	ProxyURL             string                     `yaml:"proxy_url,omitempty"`
	ProxyDisabled        bool                       `yaml:"proxy_disabled,omitempty"`
	ProxyHeaders         map[string]string          `yaml:"proxy_headers,omitempty"`
	DaemonTimeout        time.Duration              `yaml:"daemon_timeout,omitempty"`
	UserProvidedMetadata map[string]interface{}     `yaml:"-"`
	FixPermissions       *utils.FileOwner           `yaml:"-"`
	DelayEnroll          bool                       `yaml:"-"`
	FleetServer          EnrollCmdFleetServerOption `yaml:"-"`
	SkipCreateSecret     bool                       `yaml:"-"`
	SkipDaemonRestart    bool                       `yaml:"-"`
	Tags                 []string                   `yaml:"omitempty"`
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
func (e *EnrollOptions) RemoteConfig() (remote.Config, error) {
	cfg, err := remote.NewConfigFromURL(e.URL)
	if err != nil {
		return remote.Config{}, err
	}
	if cfg.Protocol == remote.ProtocolHTTP && !e.Insecure {
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

func OptionsFromMigrateAction(action *fleetapi.ActionMigrate) (EnrollOptions, error) {
	options := EnrollOptions{}
	return options, nil
}
