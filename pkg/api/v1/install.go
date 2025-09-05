// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package v1

import (
	"io"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	InstallDescriptorKind = "InstallDescriptor"
)

type OptionalTTLItem struct {
	TTL *time.Time `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

type AgentInstallDesc struct {
	OptionalTTLItem `yaml:",inline" json:",inline"`
	Version         string `yaml:"version,omitempty" json:"version,omitempty"`
	Hash            string `yaml:"hash,omitempty" json:"hash,omitempty"`
	VersionedHome   string `yaml:"versionedHome,omitempty" json:"versionedHome,omitempty"`
	Flavor          string `yaml:"flavor,omitempty" json:"flavor,omitempty"`
}

type InstallDescriptor struct {
	apiObject     `yaml:",inline"`
	AgentInstalls []AgentInstallDesc `yaml:"agentInstalls,omitempty" json:"agentInstalls,omitempty"`
}

func NewInstallDescriptor() *InstallDescriptor {
	return &InstallDescriptor{
		apiObject: apiObject{
			Version: VERSION,
			Kind:    InstallDescriptorKind,
		},
	}
}

func ParseInstallDescriptor(r io.Reader) (*InstallDescriptor, error) {
	id := NewInstallDescriptor()
	err := yaml.NewDecoder(r).Decode(id)
	return id, err
}

func WriteInstallDescriptor(w io.Writer, id *InstallDescriptor) error {
	return yaml.NewEncoder(w).Encode(id)
}
