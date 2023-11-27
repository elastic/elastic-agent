// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetessecrets

import "github.com/elastic/elastic-agent-autodiscover/kubernetes"

// Config for kubernetes provider
type Config struct {
	KubeConfig        string                       `config:"kube_config"`
	KubeClientOptions kubernetes.KubeClientOptions `config:"kube_client_options"`

	TTL string `config:"ttl"`
}

var defaultTTL = "60s"

func (c *Config) InitDefaults() {
	c.TTL = defaultTTL
}
