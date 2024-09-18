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

var (
	// Kubernetes_1_30 - Kubernetes 1.30
	Kubernetes_1_30 = define.OS{
		Type:    define.Kubernetes,
		Version: "1.30.2",
	}
	// Kubernetes_1_29 - Kubernetes 1.29
	Kubernetes_1_29 = define.OS{
		Type:    define.Kubernetes,
		Version: "1.29.4",
	}
	// Kubernetes_1_28 - Kubernetes 1.28
	Kubernetes_1_28 = define.OS{
		Type:    define.Kubernetes,
		Version: "1.28.9",
	}
)

// arches defines the list of supported architectures of Kubernetes
var arches = []string{define.AMD64, define.ARM64}

// versions defines the list of supported version of Kubernetes.
var versions = []define.OS{
	Kubernetes_1_30,
	Kubernetes_1_29,
	Kubernetes_1_28,
}

// variantToImage defines the mapping of the variants to image name.
var variantToImage = map[string]string{
	"basic":          "elastic.docker.co/beats/elastic-agent",
	"ubi":            "elastic.docker.co/beats/elastic-agent-ubi",
	"wolfi":          "elastic.docker.co/beats/elastic-agent-wolfi",
	"complete":       "elastic.docker.co/beats/elastic-agent-complete",
	"wolfi-complete": "elastic.docker.co/beats/elastic-agent-wolfi-complete",
	"cloud":          "elastic.docker.co/beats-ci/elastic-agent-cloud",
}

// GetSupported returns the list of supported OS types for Kubernetes.
func GetSupported() []define.OS {
	supported := make([]define.OS, 0, len(versions)*len(variantToImage)*2)
	for _, a := range arches {
		for _, v := range versions {
			for variant := range variantToImage {
				c := v
				c.Arch = a
				c.DockerVariant = variant
				supported = append(supported, c)
			}
		}
	}
	return supported
}

// VariantToImage returns the image name from the variant.
func VariantToImage(variant string) (string, error) {
	image, ok := variantToImage[variant]
	if !ok {
		return "", ErrUnknownDockerVariant
	}
	return image, nil
}
