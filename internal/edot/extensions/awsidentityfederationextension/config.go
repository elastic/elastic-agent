// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package awsidentityfederationextension // import "github.com/elastic/elastic-agent/internal/edot/extensions/awsidentityfederationextension"

import (
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/collector/component"

	"github.com/elastic/beats/v7/x-pack/libbeat/common/identityfederation"
)

// minAssumeRoleDuration is the smallest session duration STS accepts.
const minAssumeRoleDuration = 15 * time.Minute

// Config stores the configuration for the AWS Identity Federation extension.
//
// Only role_arn is required. The workload-identity-issuer settings default to the
// environment variables the agentless controller injects into the pod, so a managed
// integration only needs to render the role to assume.
type Config struct {
	// RoleARN is the customer IAM role assumed with sts:AssumeRoleWithWebIdentity.
	// The role trusts the Elastic workload-identity-issuer OIDC provider. Required.
	RoleARN string `mapstructure:"role_arn"`
	// SessionName is the role session name passed to STS. Optional.
	SessionName string `mapstructure:"session_name"`
	// Duration is the requested session duration. Optional; STS applies its default
	// (one hour) when unset. STS rejects values below 15 minutes.
	Duration time.Duration `mapstructure:"duration"`
	// STSRegion is the region of the STS endpoint used for the exchange. When empty,
	// the SDK's default region resolution applies (for example AWS_REGION), falling
	// back to us-east-1 like the Beats inputs do.
	STSRegion string `mapstructure:"sts_region"`

	// IssuerURL is the base URL of the workload-identity-issuer (without /token).
	// Env fallback: WORKLOAD_IDENTITY_ISSUER_URL
	IssuerURL string `mapstructure:"issuer_url"`
	// CertFile is the PEM client certificate presented to the issuer over mTLS.
	// Env fallback: WORKLOAD_IDENTITY_SSL_CERT_FILE
	CertFile string `mapstructure:"cert_file"`
	// KeyFile is the PEM private key of CertFile.
	// Env fallback: WORKLOAD_IDENTITY_SSL_KEY_FILE
	KeyFile string `mapstructure:"key_file"`
}

var _ component.Config = (*Config)(nil)

var (
	errMissingRoleARN     = errors.New("role_arn must be set")
	errNegativeDuration   = errors.New("duration must not be negative")
	errDurationTooShort   = fmt.Errorf("duration must be at least %s when set", minAssumeRoleDuration)
	errMissingIssuerURL   = fmt.Errorf("the workload-identity issuer URL must be set with issuer_url or the %s environment variable", identityfederation.WIIIssuerURLEnvVar)
	errMissingClientCerts = fmt.Errorf("the workload-identity client certificate and key must be set with cert_file and key_file or the %s and %s environment variables", identityfederation.WIISSLCertFileEnvVar, identityfederation.WIISSLKeyFileEnvVar)
)

// Validate checks the static configuration. Environment-provided settings are
// resolved at Start, so they are not validated here.
func (cfg *Config) Validate() error {
	if cfg.RoleARN == "" {
		return errMissingRoleARN
	}
	if cfg.Duration < 0 {
		return errNegativeDuration
	}
	if cfg.Duration > 0 && cfg.Duration < minAssumeRoleDuration {
		return errDurationTooShort
	}
	return nil
}

// issuerSettings is the resolved workload-identity-issuer client configuration.
type issuerSettings struct {
	issuerURL string
	certFile  string
	keyFile   string
}

// resolveIssuerSettings merges the explicit configuration with the environment
// variables set by the agentless controller. Explicit configuration wins.
func (cfg *Config) resolveIssuerSettings() (issuerSettings, error) {
	s := issuerSettings{
		issuerURL: firstNonEmpty(cfg.IssuerURL, os.Getenv(identityfederation.WIIIssuerURLEnvVar)),
		certFile:  firstNonEmpty(cfg.CertFile, os.Getenv(identityfederation.WIISSLCertFileEnvVar)),
		keyFile:   firstNonEmpty(cfg.KeyFile, os.Getenv(identityfederation.WIISSLKeyFileEnvVar)),
	}
	if s.issuerURL == "" {
		return issuerSettings{}, errMissingIssuerURL
	}
	if s.certFile == "" || s.keyFile == "" {
		return issuerSettings{}, errMissingClientCerts
	}
	return s, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
