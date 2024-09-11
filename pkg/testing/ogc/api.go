// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ogc

import "github.com/elastic/elastic-agent/pkg/testing/define"

// Layout definition for `ogc layout import`.
type Layout struct {
	Name          string            `yaml:"name"`
	Provider      string            `yaml:"provider"`
	InstanceSize  string            `yaml:"instance_size"`
	RunsOn        string            `yaml:"runs_on"`
	RemotePath    string            `yaml:"remote_path"`
	Scale         int               `yaml:"scale"`
	Username      string            `yaml:"username"`
	SSHPrivateKey string            `yaml:"ssh_private_key"`
	SSHPublicKey  string            `yaml:"ssh_public_key"`
	Ports         []string          `yaml:"ports"`
	Tags          []string          `yaml:"tags"`
	Labels        map[string]string `yaml:"labels"`
	Scripts       string            `yaml:"scripts"`
}

// Machine definition returned by `ogc up`.
type Machine struct {
	ID            int    `yaml:"id"`
	InstanceID    string `yaml:"instance_id"`
	InstanceName  string `yaml:"instance_name"`
	InstanceState string `yaml:"instance_state"`
	PrivateIP     string `yaml:"private_ip"`
	PublicIP      string `yaml:"public_ip"`
	Layout        Layout `yaml:"layout"`
	Create        string `yaml:"created"`
}

// LayoutOS defines the minimal information for a mapping of an OS to the
// provider, instance size, and runs on for that OS.
type LayoutOS struct {
	OS           define.OS
	Provider     string
	InstanceSize string
	RunsOn       string
	Username     string
	RemotePath   string
}
