// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

func TestParsePreservesFeatureSource(t *testing.T) {
	c, err := config.NewConfigFrom(`
agent:
  features:
    fqdn:
      enabled: true
    log_input_run_as_filestream:
      enabled: false
    aws_s3_v2:
      enabled: true
    future_feature:
      enabled: true
      settings:
        mode: test
`)
	require.NoError(t, err)

	flags, err := Parse(c)
	require.NoError(t, err)
	require.True(t, flags.FQDN())
	require.Equal(t, map[string]any{
		"agent": map[string]any{
			"features": map[string]any{
				"fqdn": map[string]any{
					"enabled": true,
				},
				"log_input_run_as_filestream": map[string]any{
					"enabled": false,
				},
				"aws_s3_v2": map[string]any{
					"enabled": true,
				},
				"future_feature": map[string]any{
					"enabled": true,
					"settings": map[string]any{
						"mode": "test",
					},
				},
			},
		},
	}, flags.AsProto().Source.AsMap())
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

func TestIncludeTagsInEvents(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "absent block uses default",
			yaml: `
agent:
  features:`,
			want: false,
		},
		{
			name: "explicitly disabled",
			yaml: `
agent:
  features:
    include_tags_in_events:
      enabled: false`,
			want: false,
		},
		{
			name: "enabled",
			yaml: `
agent:
  features:
    include_tags_in_events:
      enabled: true`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := config.NewConfigFrom(tt.yaml)
			require.NoError(t, err)

			flags, err := Parse(c)
			require.NoError(t, err)
			require.Equal(t, tt.want, flags.IncludeTagsInEvents())
		})
	}
}

func TestIncludeTagsInEventsReachesProtoSource(t *testing.T) {
	c, err := config.NewConfigFrom(`
agent:
  features:
    include_tags_in_events:
      enabled: true
`)
	require.NoError(t, err)

	flags, err := Parse(c)
	require.NoError(t, err)
	require.True(t, flags.IncludeTagsInEvents())

	src := flags.AsProto().Source.AsMap()
	features, ok := src["agent"].(map[string]any)["features"].(map[string]any)
	require.True(t, ok, "features key must be present in proto source")

	block, ok := features["include_tags_in_events"].(map[string]any)
	require.True(t, ok, "include_tags_in_events must be present in proto source")
	require.Equal(t, true, block["enabled"])
}
