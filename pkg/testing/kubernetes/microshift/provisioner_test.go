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
		"v1.35.0":    "quay.io/minc-org/minc:4.22.0-okd-scos.ec.10-amd64",
	}

	for version, expectedImage := range tests {
		t.Run(version, func(t *testing.T) {
			image, err := microShiftImageForKubernetesVersion(version, "amd64")
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if image != expectedImage {
				t.Fatalf("expected image %q, got %q", expectedImage, image)
			}
		})
	}
}

func TestParsePublishedPort(t *testing.T) {
	tests := []struct {
		name    string
		portOut string
		want    uint16
		wantErr bool
	}{
		{name: "ipv4", portOut: "127.0.0.1:32768\n", want: 32768},
		{name: "multiple lines uses first", portOut: "127.0.0.1:32768\n[::]:32768\n", want: 32768},
		{name: "empty", portOut: "", wantErr: true},
		{name: "no port", portOut: "127.0.0.1\n", wantErr: true},
		{name: "out of range", portOut: "127.0.0.1:70000\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePublishedPort(tt.portOut)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got port %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected port %d, got %d", tt.want, got)
			}
		})
	}
}
