// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

type Config struct {
	Enabled                bool
	SignatureValidationKey []byte
	UninstallTokenHash     string
}

type configDeserializer struct {
	// Enabled flag to indicate that protection is enabled or disabled
	Enabled bool `mapstructure:"enabled"` // TODO: rename the key to uninstall_protected when available

	// SigningKey signing key for configuration and actions signing validation
	SigningKey string `mapstructure:"signing_key"`

	// UninstallTokenHash uninstall token hash to protect Endpoint and eventually Agent from unauthorized uninstall
	UninstallTokenHash string `mapstructure:"uninstall_token_hash"`
}
