// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestOverlay(t *testing.T) {
	validProtection := map[string]interface{}{
		"id": "4d7d84e0-b46d-11ed-ba3a-57052bcc437f",
		"agent": map[string]interface{}{
			"protection": map[string]interface{}{
				"enabled":              true,
				"uninstall_token_hash": "DEADBEEF",
				"signing_key":          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEahHlKqDRfAcOZn0DmQBC7nQ8MS7CBNd8TAvBRlZl/MILX0GVsyzUmOjo+icMx+Quv7X/qVFlNjHhuBIp+7/AGA==",
			},
		},
	}

	tests := []struct {
		name         string
		src, overlay map[string]interface{}
		want         map[string]interface{}
	}{
		{
			name: "both nil",
		},
		{
			name:    "src nil",
			overlay: validProtection,
			want:    validProtection,
		},
		{
			name: "overlay nil",
			want: nil,
		},
		{
			name:    "src valid protection, overlay nil",
			src:     validProtection,
			overlay: nil,
			want:    validProtection,
		},
		{
			name: "overlay overwrite",
			src: map[string]interface{}{
				"id": "4d7d84e0-b46d-11ed-ba3a-57052bcc4355",
				"agent": map[string]interface{}{
					"protection": map[string]interface{}{
						"enabled": false,
					},
				},
			},
			overlay: validProtection,
			want:    validProtection,
		},

		{
			name: "overlay overwrite",
			src: map[string]interface{}{
				"id":    "4d7d84e0-b46d-11ed-ba3a-57052bcc4355",
				"agent": map[string]interface{}{},
			},
			overlay: validProtection,
			want:    validProtection,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := overlayPolicy(tc.src, tc.overlay)
			diff := cmp.Diff(tc.want, got)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
