// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetessecrets

import (
	"time"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

// Config for kubernetes_secrets provider
type Config struct {
	KubeConfig        string                       `config:"kube_config"`
	KubeClientOptions kubernetes.KubeClientOptions `config:"kube_client_options"`

	RefreshInterval time.Duration `config:"cache_refresh_interval" validate:"positive,nonzero"`
	TTLDelete       time.Duration `config:"cache_ttl"`
	RequestTimeout  time.Duration `config:"cache_request_timeout" validate:"positive,nonzero"`
	DisableCache    bool          `config:"cache_disable"`
}

// defaultConfig returns default configuration for kubernetes_secrets provider
func defaultConfig() *Config {
	return &Config{
		RefreshInterval: 60 * time.Second,
		TTLDelete:       1 * time.Hour,
		RequestTimeout:  5 * time.Second,
		DisableCache:    false,
	}
}
