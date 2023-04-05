// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package features

import (
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestFQDN(t *testing.T) {
	tcs := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "FQDN enabled",
			yaml: `
agent:
  features:
    fqdn:
      enabled: true`,
			want: true,
		},
		{
			name: "FQDN disabled",
			yaml: `
agent:
  features:
    fqdn:
      enabled: false`,
			want: false,
		},
		{
			name: "FQDN only {}",
			yaml: `
agent:
  features:
    fqdn: {}`,
			want: false,
		},
		{
			name: "FQDN empty",
			yaml: `
agent:
  features:
    fqdn:`,
			want: false,
		},
		{
			name: "FQDN absent",
			yaml: `
agent:
  features:`,
			want: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			c, err := config.NewConfigFrom(tc.yaml)
			if err != nil {
				t.Fatalf("could not parse config YAML: %v", err)
			}

			err = Apply(c)
			if err != nil {
				t.Fatalf("Apply failed: %v", err)
			}

			got := FQDN()
			if got != tc.want {
				t.Errorf("want: %t, got %t", tc.want, got)
			}
		})
	}
}
