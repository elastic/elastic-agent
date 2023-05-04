// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package features

import (
	"testing"

	"github.com/stretchr/testify/require"

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

func TestFQDNCallbacks(t *testing.T) {
	cb1Called, cb2Called := false, false

	err := AddFQDNOnChangeCallback(func(new, old bool) {
		cb1Called = true
	}, "cb1")
	require.NoError(t, err)

	err = AddFQDNOnChangeCallback(func(new, old bool) {
		cb2Called = true
	}, "cb2")
	require.NoError(t, err)

	defer func() {
		// Cleanup in case we don't get to the end of
		// this test successfully.
		if _, exists := current.fqdnCallbacks["cb1"]; exists {
			RemoveFQDNOnChangeCallback("cb1")
		}
		if _, exists := current.fqdnCallbacks["cb2"]; exists {
			RemoveFQDNOnChangeCallback("cb2")
		}
	}()

	require.Len(t, current.fqdnCallbacks, 2)
	current.setFQDN(false)
	require.True(t, cb1Called)
	require.True(t, cb2Called)

	RemoveFQDNOnChangeCallback("cb1")
	require.Len(t, current.fqdnCallbacks, 1)
	RemoveFQDNOnChangeCallback("cb2")
	require.Len(t, current.fqdnCallbacks, 0)
}
