// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetesleaderelection

import "github.com/elastic/elastic-agent-autodiscover/kubernetes"

// Config for kubernetes_leaderelection provider
type Config struct {
	KubeConfig string `config:"kube_config"`

	// Name of the leaderelection lease
	LeaderLease string `config:"leader_lease"`

	//Parameters to configure election process
	LeaseDuration int `config:"leader_leaseduration"`
	RenewDeadline int `config:"leader_renewdeadline"`
	RetryPeriod   int `config:"leader_retryperiod"`

	KubeClientOptions kubernetes.KubeClientOptions `config:"kube_client_options"`
}

// InitDefaults initializes the default values for the config.
func (c *Config) InitDefaults() {
	c.LeaderLease = "elastic-agent-cluster-leader"
	c.LeaseDuration = 15
	c.RenewDeadline = 10
	c.RetryPeriod = 2
}
