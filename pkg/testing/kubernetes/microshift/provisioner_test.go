// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package microshift

import (
	"runtime"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
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
			name: "MicroShift distro",
			os: define.OS{
				Type:   define.Kubernetes,
				Arch:   runtime.GOARCH,
				Distro: Name,
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

func TestMicroShiftImageForKubernetesVersion(t *testing.T) {
	tests := map[string]string{
		"1.33":       "ghcr.io/microshift-io/microshift:4.20.0_g153ff0ca9_4.20.0_okd_scos.16",
		"1.33.5":     "ghcr.io/microshift-io/microshift:4.20.0_g153ff0ca9_4.20.0_okd_scos.16",
		"v1.34.2":    "ghcr.io/microshift-io/microshift:4.21.0_g29f429c21_4.21.0_okd_scos.ec.15",
		"v1.34.2+ci": "ghcr.io/microshift-io/microshift:4.21.0_g29f429c21_4.21.0_okd_scos.ec.15",
	}

	for version, expectedImage := range tests {
		t.Run(version, func(t *testing.T) {
			image, err := microShiftImageForKubernetesVersion(version)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if image != expectedImage {
				t.Fatalf("expected image %q, got %q", expectedImage, image)
			}
		})
	}
}

func TestMicroShiftImageForKubernetesVersionErrors(t *testing.T) {
	for _, version := range []string{"", "v1.35.0", "not-a-version"} {
		t.Run(version, func(t *testing.T) {
			_, err := microShiftImageForKubernetesVersion(version)
			if err == nil {
				t.Fatalf("expected an error for Kubernetes version %q", version)
			}
		})
	}
}

func TestMicroShiftSkipDelete(t *testing.T) {
	t.Setenv("MICROSHIFT_SKIP_DELETE", "true")
	if !microShiftSkipDelete() {
		t.Fatal("expected MicroShift deletion to be skipped")
	}

	t.Setenv("MICROSHIFT_SKIP_DELETE", "false")
	if microShiftSkipDelete() {
		t.Fatal("expected MicroShift deletion not to be skipped")
	}
}
