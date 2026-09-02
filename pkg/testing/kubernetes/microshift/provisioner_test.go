// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package microshift

import (
	"runtime"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/kubernetes"
)

func TestProvisionerSupported(t *testing.T) {
	p := &provisioner{}

	tests := []struct {
		name      string
		os        define.OS
		supported bool
	}{
		{
			name: "Kubernetes host architecture",
			os: define.OS{
				Type: define.Kubernetes,
				Arch: runtime.GOARCH,
			},
			supported: true,
		},
		{
			name: "OpenShift distro",
			os: define.OS{
				Type:   define.Kubernetes,
				Arch:   runtime.GOARCH,
				Distro: kubernetes.OpenShiftDistro,
			},
			supported: true,
		},
		{
			name: "Kind distro",
			os: define.OS{
				Type:   define.Kubernetes,
				Arch:   runtime.GOARCH,
				Distro: "kind",
			},
			supported: false,
		},
		{
			name: "Linux",
			os: define.OS{
				Type: define.Linux,
				Arch: runtime.GOARCH,
			},
			supported: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := p.Supported(test.os); got != test.supported {
				t.Fatalf("Supported() = %v, want %v", got, test.supported)
			}
		})
	}
}

func TestMicroShiftImageForOpenShiftVersion(t *testing.T) {
	tests := map[string]string{
		"4.20":    "ghcr.io/microshift-io/microshift:4.20.0_g153ff0ca9_4.20.0_okd_scos.16",
		"4.20.0":  "ghcr.io/microshift-io/microshift:4.20.0_g153ff0ca9_4.20.0_okd_scos.16",
		"v4.21.2": "ghcr.io/microshift-io/microshift:4.21.0_g29f429c21_4.21.0_okd_scos.ec.15",
		"v4.22.0": "quay.io/minc-org/minc:4.22.0-okd-scos.ec.10-amd64",
	}

	for version, expectedImage := range tests {
		t.Run(version, func(t *testing.T) {
			image, err := microShiftImageForOpenShiftVersion(version, "amd64")
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if image != expectedImage {
				t.Fatalf("expected image %q, got %q", expectedImage, image)
			}
		})
	}
}
