// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline

import (
	"github.com/buildkite/buildkite-sdk/sdk/go/sdk/buildkite"
)

// Plugin versions - centralized for easy updates.
const (
	PluginVersionVaultDockerLogin = "v0.5.2"
	PluginVersionVaultSecrets     = "v0.1.0"
	PluginVersionGCPSecretManager = "v1.3.0-elastic"
	PluginVersionGoogleOIDC       = "v1.3.0"
	PluginVersionJunitAnnotate    = "v2.7.0"
	PluginVersionTestCollector    = "v1.11.0"
)

// PluginVaultDockerLogin returns the vault-docker-login plugin source and config.
func PluginVaultDockerLogin() (string, map[string]any) {
	return PluginVaultDockerLoginWithPath(VaultPathDockerRegistry)
}

// PluginVaultDockerLoginWithPath returns the vault-docker-login plugin with a custom path.
func PluginVaultDockerLoginWithPath(secretPath string) (string, map[string]any) {
	return "elastic/vault-docker-login#" + PluginVersionVaultDockerLogin, map[string]any{
		"secret_path": secretPath,
	}
}

// PluginVaultSecrets returns the vault-secrets plugin source and config.
func PluginVaultSecrets(path, field, envVar string) (string, map[string]any) {
	return "elastic/vault-secrets#" + PluginVersionVaultSecrets, map[string]any{
		"path":    path,
		"field":   field,
		"env_var": envVar,
	}
}

// PluginVaultECKeyProd returns the vault-secrets plugin for EC production API key.
func PluginVaultECKeyProd() (string, map[string]any) {
	return PluginVaultSecrets(VaultPathECKeyProd, "apiKey", "EC_API_KEY")
}

// PluginVaultECKeyStagingGov returns the vault-secrets plugin for EC staging gov API key.
func PluginVaultECKeyStagingGov() (string, map[string]any) {
	return PluginVaultSecrets(VaultPathECKeyStagingGov, "apiKey", "EC_API_KEY")
}

// PluginVaultBuildkiteAnalytics returns the vault-secrets plugin for Buildkite analytics token.
func PluginVaultBuildkiteAnalytics() (string, map[string]any) {
	return PluginVaultSecrets(VaultPathBuildkiteAnalytics, "token", "BUILDKITE_ANALYTICS_TOKEN")
}

// PluginGCPSecretManager returns the gcp-secret-manager plugin source and config.
func PluginGCPSecretManager(envSecrets map[string]string) (string, map[string]any) {
	return "elastic/gcp-secret-manager#" + PluginVersionGCPSecretManager, map[string]any{
		"env": envSecrets,
	}
}

// PluginGCPSecretManagerServerless returns the GCP secret manager plugin for serverless tests.
func PluginGCPSecretManagerServerless() (string, map[string]any) {
	return PluginGCPSecretManager(map[string]string{
		"ELASTICSEARCH_HOST":     "ea-serverless-it-elasticsearch-hostname",
		"ELASTICSEARCH_PASSWORD": "ea-serverless-it-elasticsearch-password",
		"ELASTICSEARCH_USERNAME": "ea-serverless-it-elasticsearch-username",
		"KIBANA_HOST":            "ea-serverless-it-kibana-hostname",
		"KIBANA_USERNAME":        "ea-serverless-it-kibana-username",
		"KIBANA_PASSWORD":        "ea-serverless-it-kibana-password",
	})
}

// PluginGoogleOIDC returns the Google OIDC authentication plugin source and config.
func PluginGoogleOIDC() (string, map[string]any) {
	return PluginGoogleOIDCWithConfig("elastic-observability-ci", "911195782929", 10800)
}

// PluginGoogleOIDCWithConfig returns the Google OIDC plugin with custom configuration.
func PluginGoogleOIDCWithConfig(projectID, projectNumber string, lifetimeSeconds int) (string, map[string]any) {
	return "elastic/oblt-google-auth#" + PluginVersionGoogleOIDC, map[string]any{
		"lifetime":       lifetimeSeconds,
		"project-id":     projectID,
		"project-number": projectNumber,
	}
}

// PluginJunitAnnotate returns the junit-annotate plugin source and config.
func PluginJunitAnnotate(artifactPattern string) (string, map[string]any) {
	return "junit-annotate#" + PluginVersionJunitAnnotate, map[string]any{
		"artifacts":       artifactPattern,
		"always-annotate": true,
		"run-in-docker":   false,
	}
}

// PluginTestCollector returns the test-collector plugin source and config.
func PluginTestCollector(filesPattern, format string) (string, map[string]any) {
	return "test-collector#" + PluginVersionTestCollector, map[string]any{
		"files":    filesPattern,
		"format":   format,
		"branches": "main",
		"debug":    true,
	}
}

// WithVaultDockerLogin adds the vault-docker-login plugin to a step.
func WithVaultDockerLogin(step *buildkite.CommandStep) *buildkite.CommandStep {
	source, config := PluginVaultDockerLogin()
	return AddPlugin(step, source, config)
}

// WithVaultECKeyProd adds the vault EC key prod plugin to a step.
func WithVaultECKeyProd(step *buildkite.CommandStep) *buildkite.CommandStep {
	source, config := PluginVaultECKeyProd()
	return AddPlugin(step, source, config)
}

// WithVaultECKeyStagingGov adds the vault EC key staging gov plugin to a step.
func WithVaultECKeyStagingGov(step *buildkite.CommandStep) *buildkite.CommandStep {
	source, config := PluginVaultECKeyStagingGov()
	return AddPlugin(step, source, config)
}

// WithVaultBuildkiteAnalytics adds the vault Buildkite analytics token plugin to a step.
func WithVaultBuildkiteAnalytics(step *buildkite.CommandStep) *buildkite.CommandStep {
	source, config := PluginVaultBuildkiteAnalytics()
	return AddPlugin(step, source, config)
}

// WithGoogleOIDC adds the Google OIDC plugin to a step.
func WithGoogleOIDC(step *buildkite.CommandStep) *buildkite.CommandStep {
	source, config := PluginGoogleOIDC()
	return AddPlugin(step, source, config)
}

// WithGCPSecretManagerServerless adds the GCP secret manager serverless plugin to a step.
func WithGCPSecretManagerServerless(step *buildkite.CommandStep) *buildkite.CommandStep {
	source, config := PluginGCPSecretManagerServerless()
	return AddPlugin(step, source, config)
}

// WithJunitAnnotate adds the junit-annotate plugin to a step.
func WithJunitAnnotate(step *buildkite.CommandStep, artifactPattern string) *buildkite.CommandStep {
	source, config := PluginJunitAnnotate(artifactPattern)
	return AddPlugin(step, source, config)
}

// WithTestCollector adds the test-collector plugin to a step.
func WithTestCollector(step *buildkite.CommandStep, filesPattern, format string) *buildkite.CommandStep {
	source, config := PluginTestCollector(filesPattern, format)
	return AddPlugin(step, source, config)
}
