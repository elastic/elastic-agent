// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"errors"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// ErrUnknownDockerVariant is the error returned when the variant is unknown.
var ErrUnknownDockerVariant = errors.New("unknown docker variant type")

// arches defines the list of supported architectures of Kubernetes
var arches = []string{define.AMD64, define.ARM64}

// versions defines the list of supported version of Kubernetes.
var versions = []define.OS{
	// Kubernetes 1.30
	{
		Type:    define.Kubernetes,
		Version: "1.30.2",
	},
	// Kubernetes 1.29
	{
		Type:    define.Kubernetes,
		Version: "1.29.4",
	},
	// Kubernetes 1.28
	{
		Type:    define.Kubernetes,
		Version: "1.28.9",
	},
}

// variants defines the list of variants and the image name for that variant.
//
// Note: This cannot be a simple map as the order matters. We need the
// one that we want to be the default test to be first.
var variants = []struct {
	Name  string
	Image string
}{
	{
		Name:  "basic",
		Image: "docker.elastic.co/beats/elastic-agent",
	},
	{
		Name:  "ubi",
		Image: "docker.elastic.co/beats/elastic-agent-ubi",
	},
	{
		Name:  "wolfi",
		Image: "docker.elastic.co/beats/elastic-agent-wolfi",
	},
	{
		Name:  "complete",
		Image: "docker.elastic.co/beats/elastic-agent-complete",
	},
	{
		Name:  "wolfi-complete",
		Image: "docker.elastic.co/beats/elastic-agent-wolfi-complete",
	},
	{
		Name:  "cloud",
		Image: "docker.elastic.co/beats-ci/cloud",
	},
}

// GetSupported returns the list of supported OS types for Kubernetes.
func GetSupported() []define.OS {
	supported := make([]define.OS, 0, len(versions)*len(variants)*2)
	for _, a := range arches {
		for _, v := range versions {
			for _, variant := range variants {
				c := v
				c.Arch = a
				c.DockerVariant = variant.Name
				supported = append(supported, c)
			}
		}
	}
	return supported
}

// VariantToImage returns the image name from the variant.
func VariantToImage(variant string) (string, error) {
	for _, v := range variants {
		if v.Name == variant {
			return v.Image, nil
		}
	}
	return "", ErrUnknownDockerVariant
}
