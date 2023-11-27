// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetessecrets

import (
	"time"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

// Config for kubernetes provider
type Config struct {
	KubeConfig        string                       `config:"kube_config"`
	KubeClientOptions kubernetes.KubeClientOptions `config:"kube_client_options"`

	TTLUpdate time.Duration `config:"ttl_update"`
	TTLDelete time.Duration `config:"ttl_delete"`
}

func (c *Config) InitDefaults() {
	c.TTLUpdate = 60 * time.Second
	c.TTLDelete = 1 * time.Hour
}
